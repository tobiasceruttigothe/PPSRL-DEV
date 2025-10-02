-- init.sql

-- Crear tabla usuarios
CREATE TABLE usuarios (
    id UUID PRIMARY KEY,
    fecha_registro TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Crear tabla proyectos
CREATE TABLE proyectos (
    id SERIAL PRIMARY KEY,
    usuario_id UUID NOT NULL,
    nombre VARCHAR(100) NOT NULL,
    descripcion TEXT,
    fecha_creacion TIMESTAMP NOT NULL DEFAULT NOW(),
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
);

-- Crear tabla imagenes
CREATE TABLE imagenes (
    id SERIAL PRIMARY KEY,
    proyecto_id INT NOT NULL,
    nombre VARCHAR(100) NOT NULL,
    descripcion TEXT,
    imagen BYTEA NOT NULL,
    fecha_creacion TIMESTAMP NOT NULL DEFAULT NOW(),
    FOREIGN KEY (proyecto_id) REFERENCES proyectos(id) ON DELETE CASCADE
);

-- Crear tabla logos
CREATE TABLE logos (
    id SERIAL PRIMARY KEY,
    usuario_id UUID NOT NULL,
    nombre VARCHAR(100) NOT NULL,
    logo BYTEA NOT NULL,
    fecha_creacion TIMESTAMP NOT NULL DEFAULT NOW(),
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
);

-- Índices
CREATE INDEX idx_proyectos_usuario_id ON proyectos(usuario_id);
CREATE INDEX idx_imagenes_proyecto_id ON imagenes(proyecto_id);
CREATE INDEX idx_logos_usuario_id ON logos(usuario_id);

