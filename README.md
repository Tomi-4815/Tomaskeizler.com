# Arcadia

Arcadia es un catálogo de juegos con una cuenta de creador única. Los visitantes pueden jugar juegos web directamente en el navegador y descargar juegos de PC. Solo la persona que tiene la clave de administrador puede publicar o eliminar juegos.

## Iniciar en Windows

1. Haz doble clic en `iniciar.bat`, o abre una terminal en esta carpeta y ejecuta `python app.py`.
2. La primera vez, Arcadia genera una clave de administrador y la muestra en la ventana. **Guárdala**: solo se muestra una vez.
3. Abre [http://localhost:8000](http://localhost:8000) y elige «Acceso creador».
4. Comparte la dirección pública de tu sitio; no compartas la clave de creador.

Si pierdes la clave, detén el servidor, elimina el archivo `.arcadia-admin.json` y vuelve a iniciar Arcadia. Se generará una clave nueva. Esto también cambia la clave de firma de las sesiones.

## Publicar juegos

- **Juego web:** comprime los archivos del juego en un ZIP. El archivo `index.html` debe quedar en la raíz del ZIP, no dentro de una carpeta. Se permiten ZIP de hasta 100 MB y hasta 200 MB una vez extraídos.
- **Juego de PC:** sube el instalador `.exe` o el archivo `.zip` del juego. Quedará disponible como descarga para los visitantes.
- Completa el título y la descripción en el panel del creador. Desde ese panel también puedes eliminar publicaciones.

El catálogo y los archivos se guardan localmente en `games.json` y `games/`. Haz una copia de estos junto con `.arcadia-admin.json` para respaldar el sitio.

## Hacerlo accesible a otras personas

La app se inicia en `localhost` para que solo sea accesible desde tu equipo. Para compartirla por Internet, despliega `app.py`, `index.html` y los datos en un servidor Python que mantenga almacenamiento persistente; configura un proxy con HTTPS delante y usa su dirección pública. Arcadia usa la biblioteca estándar de Python y no necesita instalar paquetes. Evita exponer directamente el servidor de desarrollo a Internet.
