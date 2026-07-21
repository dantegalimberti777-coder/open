#!/usr/bin/env bash
# Cross-compila el agente NGAV a un ejecutable de Windows (.exe) desde Linux.
#
# Requisitos:
#   - Rust con el target: rustup target add x86_64-pc-windows-gnu
#   - MinGW-w64:          apt-get install gcc-mingw-w64-x86-64
#
# Salida: endpoint/agent-core/target/x86_64-pc-windows-gnu/release/ngav.exe
# y un paquete distribuible en dist/NGAV-Windows/.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
AGENT="$ROOT/endpoint/agent-core"
TARGET="x86_64-pc-windows-gnu"

echo "==> Comprobando toolchain"
command -v x86_64-w64-mingw32-gcc >/dev/null || {
  echo "Falta MinGW-w64: apt-get install gcc-mingw-w64-x86-64"; exit 1;
}
rustup target add "$TARGET" >/dev/null 2>&1 || true

echo "==> Compilando ngav.exe ($TARGET)"
cd "$AGENT"
cargo build --release --target "$TARGET" --bin ngav

EXE="$AGENT/target/$TARGET/release/ngav.exe"
echo "==> Binario: $EXE"
file "$EXE" || true

echo "==> Empaquetando distribución"
DIST="$ROOT/dist/NGAV-Windows"
rm -rf "$DIST"; mkdir -p "$DIST"
cp "$EXE" "$DIST/NGAV.exe"
cp "$ROOT/shared/signatures/base.db" "$DIST/signatures.db"

cat > "$DIST/Iniciar NGAV.bat" <<'BAT'
@echo off
title NGAV - Antivirus de nueva generacion
echo Iniciando NGAV... se abrira la interfaz en tu navegador.
"%~dp0NGAV.exe" serve
pause
BAT

echo "==> Listo: $DIST"
ls -la "$DIST"
