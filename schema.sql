-- ============================================================
-- Sistema de Gestion de Biblioteca Escolar
-- ============================================================

DROP TABLE IF EXISTS prestamos;
DROP TABLE IF EXISTS libros;
DROP TABLE IF EXISTS autores;
DROP TABLE IF EXISTS usuarios;
DROP TABLE IF EXISTS cuentas;

-- Cuentas del sistema (login del personal del colegio).
-- Las contrasenas no se guardan en texto plano: se guarda un hash
-- generado con werkzeug.security (algoritmo scrypt).

CREATE TABLE cuentas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre_completo TEXT NOT NULL,
    usuario TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    rol TEXT NOT NULL CHECK (rol IN ('administrador', 'bibliotecario'))
);

-- Tabla de autores
CREATE TABLE autores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT NOT NULL,
    nacionalidad TEXT
);

-- Tabla de libros
CREATE TABLE libros (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    titulo TEXT NOT NULL,
    autor_id INTEGER NOT NULL,
    categoria TEXT,
    stock INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY (autor_id) REFERENCES autores(id) ON DELETE CASCADE
);

-- Tabla de usuarios (estudiantes que piden prestamos)
CREATE TABLE usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT NOT NULL,
    curso TEXT
);

-- Tabla de prestamos
CREATE TABLE prestamos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    libro_id INTEGER NOT NULL,
    usuario_id INTEGER NOT NULL,
    fecha_prestamo TEXT NOT NULL,
    fecha_devolucion TEXT,
    estado TEXT NOT NULL DEFAULT 'Prestado',
    FOREIGN KEY (libro_id) REFERENCES libros(id) ON DELETE CASCADE,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
);

-- ============================================================
-- Datos de ejemplo
-- ============================================================

-- ============================================================
-- admin / admin123        -> rol administrador
-- biblio / biblio123      -> rol bibliotecario
-- ============================================================
INSERT INTO cuentas (nombre_completo, usuario, password_hash, rol) VALUES
('Administradora del Sistema', 'admin', 'scrypt:32768:8:1$ZtND3Jxv9PIZvZFc$4eada9e864474de4de133e59f310d5fa3d20d75b219c8eccffb73e236a4da50ba9a39c974b1d0d9688e6f2e4ea0c571759d3482315d63332a234cf20f455ee1d', 'administrador'),
('Encargado de Biblioteca', 'biblio', 'scrypt:32768:8:1$37PhIWQuURZ2iYkx$531bcaa25d39254882eff80f45438b4fc971a15497f5aa4153b5b5013b475b6825a977d0aa309353e89a00f6c8c7125a17965f471c9a1a55f20096d8e0e8782e', 'bibliotecario');

INSERT INTO autores (nombre, nacionalidad) VALUES
('Gabriel García Márquez', 'Colombiana'),
('Isabel Allende', 'Chilena'),
('J.K. Rowling', 'Británica'),
('Pablo Neruda', 'Chilena'),
('Jorge Luis Borges', 'Argentina'),
('J.R.R. Tolkien', 'Británica'),
('Julio Cortázar', 'Argentina'),
('Mario Vargas Llosa', 'Peruana'),
('Agatha Christie', 'Británica'),
('Laura Esquivel', 'Mexicana');

INSERT INTO libros (titulo, autor_id, categoria, stock) VALUES
('Cien años de soledad', 1, 'Novela', 3),
('El amor en los tiempos del cólera', 1, 'Novela', 2),
('La casa de los espíritus', 2, 'Novela', 2),
('Paula', 2, 'Autobiografía', 1),
('Harry Potter y la piedra filosofal', 3, 'Fantasía', 5),
('Harry Potter y la cámara secreta', 3, 'Fantasía', 4),
('Veinte poemas de amor y una canción desesperada', 4, 'Poesía', 3),
('Ficciones', 5, 'Cuento', 2),
('El Hobbit', 6, 'Fantasía', 4),
('Rayuela', 7, 'Novela', 2),
('La ciudad y los perros', 8, 'Novela', 2),
('Asesinato en el Orient Express', 9, 'Misterio', 3),
('Como agua para chocolate', 10, 'Novela', 2);

INSERT INTO usuarios (nombre, curso) VALUES
('Juan Pérez', '3ro Medio A'),
('María Soto', '4to Medio B'),
('Camila Rojas', '2do Medio A'),
('Benjamín Muñoz', '1ro Medio C'),
('Antonia Vergara', '4to Medio A'),
('Diego Fernández', '3ro Medio B'),
('Florencia Salinas', '2do Medio B'),
('Matías Contreras', '1ro Medio A');

INSERT INTO prestamos (libro_id, usuario_id, fecha_prestamo, fecha_devolucion, estado) VALUES
(1, 1, '2026-08-01', NULL, 'Prestado'),
(6, 2, '2026-07-20', '2026-08-01', 'Devuelto'),
(3, 3, '2026-08-05', NULL, 'Prestado'),
(9, 4, '2026-07-15', '2026-07-28', 'Devuelto'),
(7, 5, '2026-08-10', NULL, 'Prestado'),
(12, 6, '2026-07-22', '2026-08-02', 'Devuelto'),
(10, 7, '2026-08-12', NULL, 'Prestado'),
(2, 8, '2026-07-25', '2026-08-04', 'Devuelto'),
(13, 1, '2026-08-14', NULL, 'Prestado'),
(5, 3, '2026-07-18', '2026-07-30', 'Devuelto');
