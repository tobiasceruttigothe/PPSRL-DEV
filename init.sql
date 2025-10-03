-- init.sql
-- Base de datos para el sistema

-- ============================================
-- TABLA: usuarios
-- ============================================
CREATE TABLE IF NOT EXISTS usuarios (
    id UUID PRIMARY KEY,
    fecha_registro TIMESTAMP NOT NULL DEFAULT NOW(),
    status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    intentos_activacion INTEGER NOT NULL DEFAULT 0,
    ultimo_intento TIMESTAMP,
    motivo_fallo TEXT,
    
    CONSTRAINT chk_status CHECK (status IN ('PENDING', 'ACTIVE', 'FAILED'))
);

-- Índices para mejorar performance
CREATE INDEX IF NOT EXISTS idx_usuarios_status ON usuarios(status);
CREATE INDEX IF NOT EXISTS idx_usuarios_fecha_registro ON usuarios(fecha_registro);

-- ============================================
-- TABLA: proyectos
-- ============================================
CREATE TABLE IF NOT EXISTS proyectos (
    id SERIAL PRIMARY KEY,
    usuario_id UUID NOT NULL,
    nombre VARCHAR(100) NOT NULL,
    descripcion TEXT,
    fecha_creacion TIMESTAMP NOT NULL DEFAULT NOW(),
    fecha_actualizacion TIMESTAMP NOT NULL DEFAULT NOW(),
    
    CONSTRAINT fk_proyectos_usuario 
        FOREIGN KEY (usuario_id) 
        REFERENCES usuarios(id) 
        ON DELETE CASCADE
);

-- Índices
CREATE INDEX IF NOT EXISTS idx_proyectos_usuario_id ON proyectos(usuario_id);
CREATE INDEX IF NOT EXISTS idx_proyectos_fecha_creacion ON proyectos(fecha_creacion);

-- ============================================
-- TABLA: imagenes
-- ============================================
CREATE TABLE IF NOT EXISTS imagenes (
    id SERIAL PRIMARY KEY,
    proyecto_id INT NOT NULL,
    nombre VARCHAR(100) NOT NULL,
    descripcion TEXT,
    imagen BYTEA NOT NULL,
    fecha_creacion TIMESTAMP NOT NULL DEFAULT NOW(),
    tamano_bytes BIGINT,
    
    CONSTRAINT fk_imagenes_proyecto 
        FOREIGN KEY (proyecto_id) 
        REFERENCES proyectos(id) 
        ON DELETE CASCADE
);

-- Índices
CREATE INDEX IF NOT EXISTS idx_imagenes_proyecto_id ON imagenes(proyecto_id);
CREATE INDEX IF NOT EXISTS idx_imagenes_fecha_creacion ON imagenes(fecha_creacion);

-- ============================================
-- TABLA: logos
-- ============================================
CREATE TABLE IF NOT EXISTS logos (
    id SERIAL PRIMARY KEY,
    usuario_id UUID NOT NULL,
    nombre VARCHAR(100) NOT NULL,
    logo BYTEA NOT NULL,
    fecha_creacion TIMESTAMP NOT NULL DEFAULT NOW(),
    tamano_bytes BIGINT,
    
    CONSTRAINT fk_logos_usuario 
        FOREIGN KEY (usuario_id) 
        REFERENCES usuarios(id) 
        ON DELETE CASCADE
);

-- Índices
CREATE INDEX IF NOT EXISTS idx_logos_usuario_id ON logos(usuario_id);
CREATE INDEX IF NOT EXISTS idx_logos_fecha_creacion ON logos(fecha_creacion);

-- ============================================
-- DATOS DE PRUEBA (opcional, para desarrollo)
-- ============================================
-- Descomentar si querés datos de prueba
-- INSERT INTO usuarios (id, fecha_registro, status, intentos_activacion) 
-- VALUES 
--     ('550e8400-e29b-41d4-a716-446655440000', NOW(), 'ACTIVE', 0),
--     ('550e8400-e29b-41d4-a716-446655440001', NOW(), 'ACTIVE', 0);

-- ============================================
-- INFORMACIÓN DE LA BASE DE DATOS
-- ============================================
-- Versión del schema
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TIMESTAMP NOT NULL DEFAULT NOW(),
    description TEXT
);

INSERT INTO schema_version (version, description) 
VALUES (1, 'Schema inicial con usuarios, proyectos, imagenes y logos')
ON CONFLICT DO NOTHING;
