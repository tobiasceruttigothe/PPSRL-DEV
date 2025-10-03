# 📦 Paper SRL - Backend

Backend del sistema Paper SRL, construido con microservicios Spring Boot, Keycloak y PostgreSQL.

## 🚀 Inicio Rápido

### Prerrequisitos

- Docker >= 20.10
- Docker Compose >= 2.0
- 4GB RAM disponible
- Puertos disponibles: 8080, 9090, 9091, 5433

### Levantar todo el backend
```bash
# 1. Clonar el repositorio
git clone https://github.com/tobiasceruttigothe/PAPERSRL-BACKEND.git
cd PAPERSRL-BACKEND

# 2. Copiar el archivo de variables de entorno
cp .env.example .env

# 3. (Opcional) Editar .env con tus configuraciones
nano .env

# 4. Levantar todos los servicios
docker-compose up -d

# 5. Esperar a que todos los servicios estén healthy (2-3 minutos)
docker-compose ps

# 6. Configurar Keycloak automáticamente
./setup-keycloak.sh
