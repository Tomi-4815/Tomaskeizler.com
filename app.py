from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import html
import json
import mimetypes
import os
import re
import secrets
import shutil
import sys
import time
import uuid
import zipfile
from email import policy
from email.parser import BytesParser
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlparse


ROOT = Path(__file__).resolve().parent
DATA_FILE = ROOT / "games.json"
ADMIN_FILE = ROOT / ".arcadia-admin.json"
GAMES_DIR = ROOT / "games"
MAX_UPLOAD = 100 * 1024 * 1024
MAX_EXTRACTED = 200 * 1024 * 1024
MAX_FILES = 1000
SESSION_SECONDS = 12 * 60 * 60


def read_games() -> list[dict]:
    try:
        with DATA_FILE.open("r", encoding="utf-8") as file:
            games = json.load(file)
        if not isinstance(games, list):
            raise ValueError("El archivo de catálogo no contiene una lista.")
        return games
    except FileNotFoundError:
        return []
    except (json.JSONDecodeError, ValueError) as error:
        raise RuntimeError(f"No se pudo leer el catálogo de juegos: {error}") from error


def write_games(games: list[dict]) -> None:
    temporary = DATA_FILE.with_suffix(".tmp")
    temporary.write_text(
        json.dumps(games, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    temporary.replace(DATA_FILE)


def load_or_create_admin() -> tuple[dict, str | None]:
    if ADMIN_FILE.exists():
        try:
            return json.loads(ADMIN_FILE.read_text(encoding="utf-8")), None
        except (OSError, json.JSONDecodeError) as error:
            raise RuntimeError(f"No se pudo leer la configuración de administrador: {error}") from error

    password = secrets.token_urlsafe(18)
    salt = secrets.token_bytes(16)
    admin = {
        "salt": base64.b64encode(salt).decode("ascii"),
        "password_hash": hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000).hex(),
        "session_key": secrets.token_hex(32),
    }
    ADMIN_FILE.write_text(json.dumps(admin), encoding="utf-8")
    try:
        ADMIN_FILE.chmod(0o600)
    except OSError:
        pass
    return admin, password


ADMIN, FIRST_PASSWORD = load_or_create_admin()
try:
    ADMIN_SALT = base64.b64decode(ADMIN["salt"], validate=True)
    ADMIN_HASH = bytes.fromhex(ADMIN["password_hash"])
    SESSION_KEY = bytes.fromhex(ADMIN["session_key"])
    if len(ADMIN_SALT) != 16 or len(ADMIN_HASH) != 32 or len(SESSION_KEY) != 32:
        raise ValueError("Tamaño de configuración no válido.")
except (KeyError, ValueError, TypeError) as error:
    raise RuntimeError(
        "La configuración de administrador está incompleta. "
        "Detén el servidor y elimina .arcadia-admin.json para generar una nueva clave."
    ) from error


def make_slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug[:48] or "juego"


class ArcadiaHandler(BaseHTTPRequestHandler):
    server_version = "Arcadia/1.0"

    def log_message(self, format: str, *args: object) -> None:
        print(f"[Arcadia] {self.address_string()} - {format % args}")

    def send_json(self, status: int, payload: dict, extra_headers: dict | None = None) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_security_headers()
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def send_security_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("X-Frame-Options", "SAMEORIGIN")

    def send_error_json(self, status: int, message: str) -> None:
        self.send_json(status, {"error": message})

    def body_bytes(self, limit: int = MAX_UPLOAD) -> bytes | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error_json(HTTPStatus.BAD_REQUEST, "Tamaño de solicitud no válido.")
            return None
        if length < 0 or length > limit:
            self.send_error_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "El archivo supera el límite de 100 MB.")
            return None
        body = self.rfile.read(length)
        if len(body) != length:
            self.send_error_json(HTTPStatus.BAD_REQUEST, "La solicitud llegó incompleta.")
            return None
        return body

    def json_body(self) -> dict | None:
        body = self.body_bytes(16 * 1024)
        if body is None:
            return None
        try:
            payload = json.loads(body.decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError
            return payload
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            self.send_error_json(HTTPStatus.BAD_REQUEST, "Solicitud JSON no válida.")
            return None

    def is_admin(self) -> bool:
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
            token = cookie["arcadia_session"].value
            encoded, signature = token.rsplit(".", 1)
            expected = hmac.new(SESSION_KEY, encoded.encode("ascii"), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(signature, expected):
                return False
            expiry = int(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)).split(b":", 1)[0])
            return expiry >= int(time.time())
        except (KeyError, ValueError, TypeError, UnicodeDecodeError):
            return False

    def session_cookie(self) -> str:
        expiry = int(time.time()) + SESSION_SECONDS
        encoded = base64.urlsafe_b64encode(f"{expiry}:{secrets.token_hex(12)}".encode()).decode().rstrip("=")
        signature = hmac.new(SESSION_KEY, encoded.encode("ascii"), hashlib.sha256).hexdigest()
        return f"arcadia_session={encoded}.{signature}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_SECONDS}"

    def do_GET(self) -> None:
        path = unquote(urlparse(self.path).path)
        if path == "/":
            self.serve_file(ROOT / "index.html", "text/html; charset=utf-8")
        elif path == "/api/games":
            self.send_json(HTTPStatus.OK, {"games": read_games()})
        elif path == "/api/session":
            self.send_json(HTTPStatus.OK, {"admin": self.is_admin()})
        elif path.startswith("/play/"):
            self.serve_game(path)
        elif path.startswith("/download/"):
            self.serve_download(path)
        else:
            self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/login":
            payload = self.json_body()
            if payload is None:
                return
            password = payload.get("password")
            if not isinstance(password, str) or len(password) > 256:
                self.send_error_json(HTTPStatus.UNAUTHORIZED, "Contraseña incorrecta.")
                return
            candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), ADMIN_SALT, 310_000)
            if not hmac.compare_digest(candidate, ADMIN_HASH):
                self.send_error_json(HTTPStatus.UNAUTHORIZED, "Contraseña incorrecta.")
                return
            self.send_json(
                HTTPStatus.OK,
                {"admin": True},
                {"Set-Cookie": self.session_cookie()},
            )
        elif path == "/api/logout":
            self.send_json(
                HTTPStatus.OK,
                {"admin": False},
                {"Set-Cookie": "arcadia_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"},
            )
        elif path == "/api/upload":
            if not self.is_admin():
                self.send_error_json(HTTPStatus.UNAUTHORIZED, "Inicia sesión como administrador para publicar.")
                return
            self.upload_game()
        elif path.startswith("/api/delete/"):
            if not self.is_admin():
                self.send_error_json(HTTPStatus.UNAUTHORIZED, "Inicia sesión como administrador para eliminar juegos.")
                return
            self.delete_game(path.removeprefix("/api/delete/"))
        else:
            self.send_error_json(HTTPStatus.NOT_FOUND, "Ruta no encontrada.")

    def serve_file(self, path: Path, content_type: str, download_name: str | None = None) -> None:
        try:
            size = path.stat().st_size
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(size))
            self.send_security_headers()
            self.send_header("Cache-Control", "no-cache")
            if download_name:
                self.send_header("Content-Disposition", f'attachment; filename="{download_name}"')
            self.end_headers()
            with path.open("rb") as file:
                shutil.copyfileobj(file, self.wfile)
        except FileNotFoundError:
            self.send_error(HTTPStatus.NOT_FOUND)
        except OSError as error:
            print(f"[Arcadia] No se pudo servir {path}: {error}", file=sys.stderr)
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)

    def game_by_id(self, game_id: str) -> dict | None:
        return next((game for game in read_games() if game.get("id") == game_id), None)

    def serve_game(self, path: str) -> None:
        parts = path.removeprefix("/play/").split("/", 1)
        game = self.game_by_id(parts[0])
        if not game or game.get("type") != "web":
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        relative = parts[1] if len(parts) > 1 and parts[1] else "index.html"
        target = (GAMES_DIR / game["id"] / "web" / relative).resolve()
        game_root = (GAMES_DIR / game["id"] / "web").resolve()
        if not target.is_relative_to(game_root) or not target.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        mime_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        if mime_type.startswith("text/") or mime_type in ("application/javascript", "application/json"):
            mime_type += "; charset=utf-8"
        self.serve_file(target, mime_type)

    def serve_download(self, path: str) -> None:
        game_id = path.removeprefix("/download/")
        game = self.game_by_id(game_id)
        if not game or game.get("type") != "pc":
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        target = GAMES_DIR / game_id / game["file"]
        self.serve_file(target, "application/octet-stream", game["file"])

    def upload_game(self) -> None:
        content_type = self.headers.get("Content-Type", "")
        if not content_type.lower().startswith("multipart/form-data;"):
            self.send_error_json(HTTPStatus.BAD_REQUEST, "El formulario de publicación no es válido.")
            return
        body = self.body_bytes()
        if body is None:
            return
        try:
            message = BytesParser(policy=policy.default).parsebytes(
                f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("ascii") + body
            )
            fields: dict[str, str] = {}
            upload = None
            for part in message.iter_parts():
                name = part.get_param("name", header="content-disposition")
                data = part.get_payload(decode=True) or b""
                if name == "file":
                    upload = (part.get_filename() or "", data)
                elif name:
                    fields[name] = data.decode("utf-8").strip()
        except (UnicodeDecodeError, ValueError, AttributeError) as error:
            self.send_error_json(HTTPStatus.BAD_REQUEST, f"Formulario no válido: {error}")
            return

        title = fields.get("title", "")
        description = fields.get("description", "")
        game_type = fields.get("type", "")
        if not title or len(title) > 60 or not description or len(description) > 300:
            self.send_error_json(HTTPStatus.BAD_REQUEST, "Añade un título (máx. 60 caracteres) y una descripción (máx. 300).")
            return
        if game_type not in ("web", "pc") or not upload or not upload[1]:
            self.send_error_json(HTTPStatus.BAD_REQUEST, "Selecciona un archivo para el tipo de juego elegido.")
            return

        original_name, file_data = upload
        extension = Path(original_name).suffix.lower()
        if game_type == "web" and extension != ".zip":
            self.send_error_json(HTTPStatus.BAD_REQUEST, "Los juegos web se publican como archivo .zip.")
            return
        if game_type == "pc" and extension not in (".zip", ".exe"):
            self.send_error_json(HTTPStatus.BAD_REQUEST, "Los juegos de PC deben ser archivos .zip o .exe.")
            return

        games = read_games()
        game_id = f"{make_slug(title)}-{uuid.uuid4().hex[:8]}"
        destination = GAMES_DIR / game_id
        try:
            destination.mkdir(parents=True, exist_ok=False)
            if game_type == "web":
                self.extract_web_game(file_data, destination / "web")
            else:
                safe_name = f"{make_slug(title)}{extension}"
                (destination / safe_name).write_bytes(file_data)
            game = {
                "id": game_id,
                "title": title,
                "description": description,
                "type": game_type,
                "created": int(time.time()),
                **({"file": safe_name} if game_type == "pc" else {}),
            }
            write_games([game, *games])
        except (ValueError, OSError, zipfile.BadZipFile) as error:
            shutil.rmtree(destination, ignore_errors=True)
            self.send_error_json(HTTPStatus.BAD_REQUEST, f"No se pudo publicar el juego: {error}")
            return
        self.send_json(HTTPStatus.CREATED, {"game": game})

    @staticmethod
    def extract_web_game(data: bytes, destination: Path) -> None:
        try:
            archive = zipfile.ZipFile(__import__("io").BytesIO(data))
        except zipfile.BadZipFile as error:
            raise ValueError("el archivo ZIP está dañado.") from error
        with archive:
            entries = archive.infolist()
            if len(entries) > MAX_FILES:
                raise ValueError(f"el ZIP no puede contener más de {MAX_FILES} archivos.")
            expanded = 0
            root_index = False
            for entry in entries:
                name = entry.filename.replace("\\", "/")
                relative = PurePosixPath(name)
                if relative.is_absolute() or any(
                    part in ("", ".", "..") or ":" in part for part in relative.parts
                ):
                    if entry.is_dir() and name.endswith("/"):
                        continue
                    raise ValueError("el ZIP contiene una ruta no válida.")
                if entry.flag_bits & 1 or (entry.external_attr >> 16) & 0o170000 == 0o120000:
                    raise ValueError("no se permiten archivos cifrados ni enlaces simbólicos.")
                expanded += entry.file_size
                if expanded > MAX_EXTRACTED:
                    raise ValueError("el contenido descomprimido supera 200 MB.")
                if entry.file_size > MAX_EXTRACTED or (
                    entry.file_size > 1_000_000 and entry.compress_size == 0
                ) or (
                    entry.compress_size > 0 and entry.file_size > max(entry.compress_size * 200, 10_000_000)
                ):
                    raise ValueError("el ZIP contiene un archivo con una compresión no permitida.")
                target = destination.joinpath(*relative.parts)
                if entry.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if name == "index.html":
                    root_index = True
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(entry) as source, target.open("wb") as output:
                    shutil.copyfileobj(source, output)
            if not root_index:
                raise ValueError("el ZIP debe tener un index.html en la raíz.")

    def delete_game(self, game_id: str) -> None:
        games = read_games()
        remaining = [game for game in games if game.get("id") != game_id]
        if len(remaining) == len(games):
            self.send_error_json(HTTPStatus.NOT_FOUND, "No se encontró ese juego.")
            return
        write_games(remaining)
        shutil.rmtree(GAMES_DIR / game_id, ignore_errors=True)
        self.send_json(HTTPStatus.OK, {"deleted": True})


def main() -> None:
    parser = argparse.ArgumentParser(description="Servidor web de Arcadia")
    parser.add_argument("--host", default="127.0.0.1", help="Dirección de escucha (por defecto: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Puerto web (por defecto: 8000)")
    arguments = parser.parse_args()
    GAMES_DIR.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer((arguments.host, arguments.port), ArcadiaHandler)
    print(f"Arcadia está disponible en http://localhost:{arguments.port}")
    if FIRST_PASSWORD:
        print("\nCLAVE DE ADMINISTRADOR (guárdala; se muestra una sola vez):")
        print(FIRST_PASSWORD)
        print("Solo comparte la dirección pública, nunca esta clave.\n")
    print("Detén el servidor con Ctrl+C.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nCerrando Arcadia...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
