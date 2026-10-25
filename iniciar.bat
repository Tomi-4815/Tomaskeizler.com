@echo off
cd /d "%~dp0"
python app.py
if errorlevel 1 (
  echo.
  echo Arcadia no pudo iniciarse. Comprueba que Python este instalado.
  pause
)
