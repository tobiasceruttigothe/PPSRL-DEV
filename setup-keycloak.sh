#!/bin/bash

# ============================================
# PAPER SRL - Keycloak Setup Script
# ============================================
# Este script configura automáticamente Keycloak
# con el realm, roles y cliente necesarios

set -e

echo "🔧 Iniciando configuración de Keycloak..."

# Configuración
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
ADMIN_USER="${KEYCLOAK_ADMIN:-admin}"
ADMIN_PASS="${KEYCLOAK_ADMIN_PASSWORD:-admin}"
REALM_NAME="tesina"
CLIENT_ID="backend-service"
CLIENT_SECRET="${KEYCLOAK_CLIENT_SECRET:-siZIjoNYryGmXBPAhafsYMTyW0WtnU6z}"

# Esperar a que Keycloak esté disponible
echo "⏳ Esperando a que Keycloak esté disponible..."
MAX_RETRIES=30
RETRY_COUNT=0

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if curl -sf "${KEYCLOAK_URL}/health/ready" > /dev/null 2>&1; then
        echo "✅ Keycloak está disponible"
        break
    fi
    echo "   Intento $((RETRY_COUNT + 1))/$MAX_RETRIES..."
    sleep 5
    RETRY_COUNT=$((RETRY_COUNT + 1))
done

if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
    echo "❌ Error: Keycloak no está disponible después de $MAX_RETRIES intentos"
    exit 1
fi

# Obtener token de administrador
echo "🔑 Obteniendo token de administrador..."
TOKEN_RESPONSE=$(curl -s -X POST "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=${ADMIN_USER}" \
  -d "password=${ADMIN_PASS}" \
  -d "grant_type=password" \
  -d "client_id=admin-cli")

ACCESS_TOKEN=$(echo $TOKEN_RESPONSE | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

if [ -z "$ACCESS_TOKEN" ]; then
    echo "❌ Error: No se pudo obtener el token de administrador"
    echo "Respuesta: $TOKEN_RESPONSE"
    exit 1
fi

echo "✅ Token obtenido"

# Verificar si el realm ya existe
echo "🔍 Verificando si el realm '$REALM_NAME' existe..."
REALM_EXISTS=$(curl -s -o /dev/null -w "%{http_code}" \
  "${KEYCLOAK_URL}/admin/realms/${REALM_NAME}" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}")

if [ "$REALM_EXISTS" == "200" ]; then
    echo "⚠️  El realm '$REALM_NAME' ya existe. Saltando creación."
else
    echo "📝 Creando realm '$REALM_NAME'..."
    
    REALM_JSON='{
      "realm": "'${REALM_NAME}'",
      "enabled": true,
      "displayName": "Paper SRL",
      "registrationAllowed": false,
      "resetPasswordAllowed": true,
      "rememberMe": true,
      "verifyEmail": true,
      "loginWithEmailAllowed": true,
      "duplicateEmailsAllowed": false,
      "sslRequired": "none",
      "accessTokenLifespan": 3600,
      "accessTokenLifespanForImplicitFlow": 900,
      "ssoSessionIdleTimeout": 1800,
      "ssoSessionMaxLifespan": 36000
    }'
    
    curl -s -X POST "${KEYCLOAK_URL}/admin/realms" \
      -H "Authorization: Bearer ${ACCESS_TOKEN}" \
      -H "Content-Type: application/json" \
      -d "$REALM_JSON"
    
    echo "✅ Realm creado"
fi

# Crear roles
echo "👥 Creando roles..."

for ROLE in "ADMIN" "CLIENTE" "INTERESADO"; do
    ROLE_EXISTS=$(curl -s -o /dev/null -w "%{http_code}" \
      "${KEYCLOAK_URL}/admin/realms/${REALM_NAME}/roles/${ROLE}" \
      -H "Authorization: Bearer ${ACCESS_TOKEN}")
    
    if [ "$ROLE_EXISTS" == "200" ]; then
        echo "   ⚠️  Rol '$ROLE' ya existe"
    else
        ROLE_JSON='{
          "name": "'${ROLE}'",
          "description": "Rol '${ROLE}'"
        }'
        
        curl -s -X POST "${KEYCLOAK_URL}/admin/realms/${REALM_NAME}/roles" \
          -H "Authorization: Bearer ${ACCESS_TOKEN}" \
          -H "Content-Type: application/json" \
          -d "$ROLE_JSON"
        
        echo "   ✅ Rol '$ROLE' creado"
    fi
done

# Crear cliente para backend
echo "🔌 Configurando cliente '$CLIENT_ID'..."

CLIENT_EXISTS=$(curl -s "${KEYCLOAK_URL}/admin/realms/${REALM_NAME}/clients" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" | \
  grep -o "\"clientId\":\"${CLIENT_ID}\"")

if [ -n "$CLIENT_EXISTS" ]; then
    echo "⚠️  Cliente '$CLIENT_ID' ya existe"
else
    CLIENT_JSON='{
      "clientId": "'${CLIENT_ID}'",
      "name": "Backend Service",
      "description": "Cliente para microservicios backend",
      "enabled": true,
      "clientAuthenticatorType": "client-secret",
      "secret": "'${CLIENT_SECRET}'",
      "redirectUris": ["*"],
      "webOrigins": ["*"],
      "protocol": "openid-connect",
      "publicClient": false,
      "serviceAccountsEnabled": true,
      "directAccessGrantsEnabled": true,
      "standardFlowEnabled": true,
      "implicitFlowEnabled": false,
      "fullScopeAllowed": true,
      "attributes": {
        "access.token.lifespan": "3600"
      }
    }'
    
    curl -s -X POST "${KEYCLOAK_URL}/admin/realms/${REALM_NAME}/clients" \
      -H "Authorization: Bearer ${ACCESS_TOKEN}" \
      -H "Content-Type: application/json" \
      -d "$CLIENT_JSON"
    
    echo "✅ Cliente creado"
fi

# Obtener ID del service account del cliente
echo "🔑 Configurando permisos del service account..."

CLIENT_UUID=$(curl -s "${KEYCLOAK_URL}/admin/realms/${REALM_NAME}/clients" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" | \
  grep -o "\"id\":\"[^\"]*\",\"clientId\":\"${CLIENT_ID}\"" | \
  grep -o "\"id\":\"[^\"]*" | cut -d'"' -f4)

if [ -z "$CLIENT_UUID" ]; then
    echo "❌ Error: No se pudo obtener el UUID del cliente"
    exit 1
fi

# Asignar roles realm-management al service account
SERVICE_ACCOUNT_USER=$(curl -s "${KEYCLOAK_URL}/admin/realms/${REALM_NAME}/clients/${CLIENT_UUID}/service-account-user" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" | \
  grep -o "\"id\":\"[^\"]*" | head -1 | cut -d'"' -f4)

if [ -n "$SERVICE_ACCOUNT_USER" ]; then
    echo "📋 Asignando permisos de administración al service account..."
    
    # Obtener cliente realm-management
    REALM_MGMT_CLIENT=$(curl -s "${KEYCLOAK_URL}/admin/realms/${REALM_NAME}/clients" \
      -H "Authorization: Bearer ${ACCESS_TOKEN}" | \
      grep -o "\"id\":\"[^\"]*\",\"clientId\":\"realm-management\"" | \
      grep -o "\"id\":\"[^\"]*" | cut -d'"' -f4)
    
    # Obtener roles disponibles
    ROLES_JSON=$(curl -s "${KEYCLOAK_URL}/admin/realms/${REALM_NAME}/users/${SERVICE_ACCOUNT_USER}/role-mappings/clients/${REALM_MGMT_CLIENT}/available" \
      -H "Authorization: Bearer ${ACCESS_TOKEN}")
    
    # Asignar todos los roles de realm-management
    curl -s -X POST "${KEYCLOAK_URL}/admin/realms/${REALM_NAME}/users/${SERVICE_ACCOUNT_USER}/role-mappings/clients/${REALM_MGMT_CLIENT}" \
      -H "Authorization: Bearer ${ACCESS_TOKEN}" \
      -H "Content-Type: application/json" \
      -d "$ROLES_JSON"
    
    echo "✅ Permisos asignados"
fi

echo ""
echo "🎉 ¡Configuración de Keycloak completada!"
echo ""
echo "📌 Información de acceso:"
echo "   URL Admin: ${KEYCLOAK_URL}/admin"
echo "   Usuario: ${ADMIN_USER}"
echo "   Contraseña: ${ADMIN_PASS}"
echo "   Realm: ${REALM_NAME}"
echo ""
echo "📌 Información del cliente:"
echo "   Client ID: ${CLIENT_ID}"
echo "   Client Secret: ${CLIENT_SECRET}"
echo ""
