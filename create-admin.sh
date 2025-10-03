#!/bin/bash

# ============================================
# Crear usuario administrador inicial
# ============================================

set -e

echo "👤 Creando usuario administrador..."

API_URL="http://localhost:9091"

# Datos del admin
read -p "Username del admin: " ADMIN_USERNAME
read -p "Email del admin: " ADMIN_EMAIL
read -p "Razón Social: " RAZON_SOCIAL
read -sp "Contraseña (min 8 caracteres): " ADMIN_PASSWORD
echo ""

# Crear usuario
echo "📝 Creando usuario..."
#RESPONSE=$(curl -s -X POST "${API_URL}/api/usuarios/create" \
#  -H "Content-Type: application/json" \
#  -d "{
#    \"username\": \"${ADMIN_USERNAME}\",
#    \"email\": \"${ADMIN_EMAIL}\",
RESPONSE=$(curl -s -X POST "${API_URL}/api/usuarios/create" \
  -H "Content-Type: application/json" \
  -d "{
    \"username\": \"${ADMIN_USERNAME}\",
    \"email\": \"${ADMIN_EMAIL}\",
    \"razonSocial\": \"${RAZON_SOCIAL}\",
    \"password\": \"${ADMIN_PASSWORD}\"
  }")

