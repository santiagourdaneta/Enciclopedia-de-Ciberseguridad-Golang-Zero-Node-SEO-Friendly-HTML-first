#!/bin/bash

# Configuración
APP_NAME="ciber-app"
BUILD_DIR="./build"

echo "🚀 Iniciando despliegue de Ciberseguridad Pro..."

# 1. Limpiar y crear carpeta de build
rm -rf $BUILD_DIR
mkdir -p $BUILD_DIR

# 2. Compilar el binario para Linux (Arquitectura de servidor común)
echo "📦 Compilando binario para producción..."
GOOS=linux GOARCH=amd64 go build -o $BUILD_DIR/$APP_NAME main.go

# 3. Copiar carpetas necesarias (Plantillas y estáticos)
echo "📂 Copiando recursos..."
cp -r templates $BUILD_DIR/
cp -r static $BUILD_DIR/ 2>/dev/null || :

echo "✅ Build completado en la carpeta $BUILD_DIR"
echo "👉 Para subirlo usa: scp -r $BUILD_DIR/* usuario@tu-servidor:/var/www/ciber-app"