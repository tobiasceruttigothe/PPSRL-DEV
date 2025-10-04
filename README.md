# 📦 Paper SRL - Backend

Backend del sistema Paper SRL, construido con una arquitectura de microservicios utilizando Spring Boot, Spring Cloud Gateway, Keycloak y PostgreSQL, todo orquestado con Docker.

## ✨ Arquitectura

El sistema se compone de los siguientes servicios, todos gestionados a través del archivo `docker-compose.yml`:

-   **`api-gateway`**: (Puerto `9090`) Punto de entrada único para todas las peticiones al backend. Se encarga del enrutamiento, la seguridad y el balanceo de carga.
-   **`users-service`**: (Puerto `9091`) Microservicio para la gestión de usuarios, incluyendo el registro, la autenticación y la lógica de negocio relacionada.
-   **`keycloak`**: (Puerto `8080`) Servidor de autenticación y autorización. Gestiona los usuarios, roles y la seguridad de la aplicación.
-   **`kc-postgres`**: Base de datos PostgreSQL para Keycloak.
-   **`app-postgres`**: (Puerto `5433`) Base de datos PostgreSQL para los microservicios de la aplicación (como `users-service`).

## 🚀 Inicio Rápido

### Prerrequisitos

-   Docker >= 20.10
-   Docker Compose >= 2.0
-   ~4GB de RAM disponible
-   Puertos libres: `8080`, `9090`, `9091`, `5433`

### ¡Un solo comando para gobernarlos a todos!

Para levantar todo el entorno de backend, simplemente clona el repositorio y ejecuta Docker Compose:

```bash
# 1. Clona el repositorio
git clone https://github.com/tobiasceruttigothe/PAPERSRL-BACKEND.git
cd PAPERSRL-BACKEND

# 2. Levanta todos los servicios en segundo plano
docker-compose up --build -d
```

Después de 2-3 minutos, todos los servicios deberían estar iniciados y saludables. Puedes verificar su estado con:

```bash
docker-compose ps
```

¡Eso es todo! El entorno está completamente configurado y listo para usarse.

## 🔑 Puntos de Acceso y Credenciales

Una vez que todo esté en funcionamiento, puedes acceder a los siguientes servicios:

-   **API Gateway**:
    -   URL: `http://localhost:9090`

-   **Documentación de la API (Swagger UI)**:
    -   URL: `http://localhost:9090/swagger-ui.html`
    -   Desde aquí puedes explorar y probar los endpoints del `users-service`.

-   **Consola de Administración de Keycloak**:
    -   URL: `http://localhost:8080`
    -   Usuario: `admin`
    -   Contraseña: `admin`
    -   **Realm configurado**: `tesina`

## ✅ Configuración Automática

No necesitas ejecutar ningún script de configuración manual. Al iniciar, Docker Compose se encarga de:

1.  **Construir las imágenes** de los microservicios.
2.  **Inicializar las bases de datos**.
3.  **Configurar Keycloak automáticamente**: El realm `tesina`, los roles (`ADMIN`, `INTERESADO`, `CLIENTE`) y el cliente (`backend-service`) se crean e importan desde el archivo `tesina-realm.json`.

Este enfoque garantiza un entorno de desarrollo consistente y reproducible para todos los miembros del equipo.