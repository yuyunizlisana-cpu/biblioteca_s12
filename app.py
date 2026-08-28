"""
Sistema de Gestion de Biblioteca Escolar

Cuentas de demostracion:
    admin  / admin123    -> rol administrador
    biblio / biblio123   -> rol bibliotecario
"""

import os
import re
import secrets
import sqlite3
from datetime import date
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    session, abort
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# ---------------------------------------------------------------
# SEGURIDAD: clave secreta
# La clave se lee de una variable de entorno (SECRET_KEY). Si no
# existe (por ejemplo, en desarrollo local), se genera una al azar
# cada vez que arranca el servidor. En produccion (Render) se debe
# configurar SECRET_KEY como variable de entorno para que las
# sesiones de los usuarios no se invaliden cada vez que el servidor
# se reinicia, y para que nadie pueda adivinarla.
# ---------------------------------------------------------------
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# Cookies de sesion mas seguras
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,   # JavaScript no puede leer la cookie
    SESSION_COOKIE_SAMESITE="Lax",  # mitiga CSRF desde otros sitios
)

DB_NAME = "biblioteca.db"


def asegurar_base_datos():
    """Crea la base de datos automaticamente si aun no existe."""
    if not os.path.exists(DB_NAME):
        conn = sqlite3.connect(DB_NAME)
        with open("schema.sql", "r", encoding="utf-8") as f:
            conn.executescript(f.read())
        conn.commit()
        conn.close()


asegurar_base_datos()


def get_db():
    """Abre una conexion a la base de datos y permite acceder a las filas como diccionarios."""
    conn = sqlite3.connect(DB_NAME)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    return conn


# =================================================================
# SEGURIDAD: proteccion CSRF (Cross-Site Request Forgery)
# Cada sesion recibe un token unico. Todo formulario incluye ese
# token en un campo oculto. Antes de procesar cualquier POST, se
# valida que el token recibido coincida con el de la sesion; si no
# coincide (o falta), se rechaza la peticion con un error 403.
# Esto evita que un sitio malicioso pueda enviar formularios en
# nombre de un usuario que tiene una sesion activa en esta app.
# =================================================================
def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def validar_csrf():
    if request.method == "POST":
        token_form = request.form.get("csrf_token", "")
        token_sesion = session.get("csrf_token", "")
        if not token_form or token_form != token_sesion:
            abort(403)


# =================================================================
# SEGURIDAD: autenticacion y autorizacion por rol
# =================================================================
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "cuenta_id" not in session:
            flash("Debes iniciar sesión para continuar.", "danger")
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return wrapper


def role_required(*roles_permitidos):
    """Exige ademas que el rol de la cuenta este entre los permitidos."""
    def decorador(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if "cuenta_id" not in session:
                flash("Debes iniciar sesión para continuar.", "danger")
                return redirect(url_for("login", next=request.path))
            if session.get("rol") not in roles_permitidos:
                abort(403)
            return f(*args, **kwargs)
        return wrapper
    return decorador


@app.context_processor
def inyectar_usuario_actual():
    return {
        "usuario_actual": session.get("nombre_completo"),
        "rol_actual": session.get("rol"),
    }


# ---------------------------------------------------------------
# LOGIN / LOGOUT
# ---------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if "cuenta_id" in session:
        return redirect(url_for("index"))

    if request.method == "POST":
        usuario = request.form.get("usuario", "").strip()
        password = request.form.get("password", "")

        conn = get_db()
        cuenta = conn.execute(
            "SELECT * FROM cuentas WHERE usuario = ?", (usuario,)
        ).fetchone()
        conn.close()

        # Se usa el mismo mensaje generico tanto si el usuario no existe
        # como si la contrasena es incorrecta, para no revelar cuales
        # nombres de usuario existen realmente en el sistema.
        if cuenta is None or not check_password_hash(cuenta["password_hash"], password):
            flash("Usuario o contraseña incorrectos.", "danger")
            return render_template("login.html")

        session.clear()
        session["cuenta_id"] = cuenta["id"]
        session["nombre_completo"] = cuenta["nombre_completo"]
        session["rol"] = cuenta["rol"]
        flash(f"Bienvenido/a, {cuenta['nombre_completo']}.", "success")

        destino = request.args.get("next") or url_for("index")
        return redirect(destino)

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("Sesión cerrada correctamente.", "info")
    return redirect(url_for("login"))


# ---------------------------------------------------------------
# INICIO
# ---------------------------------------------------------------
@app.route("/")
@login_required
def index():
    conn = get_db()
    total_libros = conn.execute("SELECT COUNT(*) AS c FROM libros").fetchone()["c"]
    total_autores = conn.execute("SELECT COUNT(*) AS c FROM autores").fetchone()["c"]
    total_usuarios = conn.execute("SELECT COUNT(*) AS c FROM usuarios").fetchone()["c"]
    prestamos_activos = conn.execute(
        "SELECT COUNT(*) AS c FROM prestamos WHERE estado = 'Prestado'"
    ).fetchone()["c"]
    conn.close()
    return render_template(
        "index.html",
        total_libros=total_libros,
        total_autores=total_autores,
        total_usuarios=total_usuarios,
        prestamos_activos=prestamos_activos,
    )


# =================================================================
# VALIDACIONES DE DATOS (Criterio 3.3: evitar datos invalidos o
# maliciosos antes de que lleguen a la base de datos)
# =================================================================
def validar_texto(valor, campo, minimo=1, maximo=100, obligatorio=True):
    errores = []
    valor = (valor or "").strip()
    if obligatorio and len(valor) < minimo:
        errores.append(f"El campo '{campo}' es obligatorio.")
    if len(valor) > maximo:
        errores.append(f"El campo '{campo}' no puede superar {maximo} caracteres.")
    return errores


def validar_entero_no_negativo(valor, campo):
    try:
        n = int(valor)
    except (TypeError, ValueError):
        return [f"El campo '{campo}' debe ser un número entero."], None
    if n < 0:
        return [f"El campo '{campo}' no puede ser negativo."], None
    return [], n


# ---------------------------------------------------------------
# CRUD: AUTORES  (lectura: ambos roles / escritura: solo administrador)
# ---------------------------------------------------------------
@app.route("/autores")
@login_required
def listar_autores():
    conn = get_db()
    autores = conn.execute("SELECT * FROM autores ORDER BY nombre").fetchall()
    conn.close()
    return render_template("autores.html", autores=autores)


@app.route("/autores/nuevo", methods=["GET", "POST"])
@role_required("administrador")
def crear_autor():
    if request.method == "POST":
        nombre = request.form.get("nombre", "").strip()
        nacionalidad = request.form.get("nacionalidad", "").strip()

        errores = validar_texto(nombre, "Nombre", maximo=100)
        errores += validar_texto(nacionalidad, "Nacionalidad", maximo=60, obligatorio=False)

        if errores:
            for e in errores:
                flash(e, "danger")
            return render_template("autor_form.html", autor=request.form)

        conn = get_db()
        conn.execute(
            "INSERT INTO autores (nombre, nacionalidad) VALUES (?, ?)",
            (nombre, nacionalidad),
        )
        conn.commit()
        conn.close()
        flash("Autor agregado correctamente.", "success")
        return redirect(url_for("listar_autores"))
    return render_template("autor_form.html", autor=None)


@app.route("/autores/editar/<int:id>", methods=["GET", "POST"])
@role_required("administrador")
def editar_autor(id):
    conn = get_db()
    if request.method == "POST":
        nombre = request.form.get("nombre", "").strip()
        nacionalidad = request.form.get("nacionalidad", "").strip()

        errores = validar_texto(nombre, "Nombre", maximo=100)
        errores += validar_texto(nacionalidad, "Nacionalidad", maximo=60, obligatorio=False)

        if errores:
            conn.close()
            for e in errores:
                flash(e, "danger")
            return render_template("autor_form.html", autor=request.form)

        conn.execute(
            "UPDATE autores SET nombre = ?, nacionalidad = ? WHERE id = ?",
            (nombre, nacionalidad, id),
        )
        conn.commit()
        conn.close()
        flash("Autor actualizado correctamente.", "success")
        return redirect(url_for("listar_autores"))
    autor = conn.execute("SELECT * FROM autores WHERE id = ?", (id,)).fetchone()
    conn.close()
    if autor is None:
        abort(404)
    return render_template("autor_form.html", autor=autor)


@app.route("/autores/eliminar/<int:id>", methods=["POST"])
@role_required("administrador")
def eliminar_autor(id):
    conn = get_db()
    conn.execute("DELETE FROM autores WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    flash("Autor eliminado.", "info")
    return redirect(url_for("listar_autores"))


# ---------------------------------------------------------------
# CRUD: LIBROS  (ambos roles)
# ---------------------------------------------------------------
@app.route("/libros")
@login_required
def listar_libros():
    conn = get_db()
    libros = conn.execute(
        """SELECT libros.id, libros.titulo, libros.categoria, libros.stock,
                  autores.nombre AS autor_nombre
           FROM libros
           JOIN autores ON libros.autor_id = autores.id
           ORDER BY libros.titulo"""
    ).fetchall()
    conn.close()
    return render_template("libros.html", libros=libros)


@app.route("/libros/nuevo", methods=["GET", "POST"])
@login_required
def crear_libro():
    conn = get_db()
    if request.method == "POST":
        titulo = request.form.get("titulo", "").strip()
        autor_id = request.form.get("autor_id", "")
        categoria = request.form.get("categoria", "").strip()
        stock_raw = request.form.get("stock", "")

        errores = validar_texto(titulo, "Título", maximo=150)
        errores += validar_texto(categoria, "Categoría", maximo=60, obligatorio=False)
        errores_stock, stock = validar_entero_no_negativo(stock_raw, "Stock")
        errores += errores_stock

        autor = conn.execute("SELECT id FROM autores WHERE id = ?", (autor_id,)).fetchone()
        if autor is None:
            errores.append("Debes seleccionar un autor válido.")

        if errores:
            autores = conn.execute("SELECT * FROM autores ORDER BY nombre").fetchall()
            conn.close()
            for e in errores:
                flash(e, "danger")
            return render_template("libro_form.html", libro=request.form, autores=autores)

        conn.execute(
            "INSERT INTO libros (titulo, autor_id, categoria, stock) VALUES (?, ?, ?, ?)",
            (titulo, autor_id, categoria, stock),
        )
        conn.commit()
        conn.close()
        flash("Libro agregado correctamente.", "success")
        return redirect(url_for("listar_libros"))
    autores = conn.execute("SELECT * FROM autores ORDER BY nombre").fetchall()
    conn.close()
    return render_template("libro_form.html", libro=None, autores=autores)


@app.route("/libros/editar/<int:id>", methods=["GET", "POST"])
@login_required
def editar_libro(id):
    conn = get_db()
    if request.method == "POST":
        titulo = request.form.get("titulo", "").strip()
        autor_id = request.form.get("autor_id", "")
        categoria = request.form.get("categoria", "").strip()
        stock_raw = request.form.get("stock", "")

        errores = validar_texto(titulo, "Título", maximo=150)
        errores += validar_texto(categoria, "Categoría", maximo=60, obligatorio=False)
        errores_stock, stock = validar_entero_no_negativo(stock_raw, "Stock")
        errores += errores_stock

        autor = conn.execute("SELECT id FROM autores WHERE id = ?", (autor_id,)).fetchone()
        if autor is None:
            errores.append("Debes seleccionar un autor válido.")

        if errores:
            autores = conn.execute("SELECT * FROM autores ORDER BY nombre").fetchall()
            conn.close()
            for e in errores:
                flash(e, "danger")
            return render_template("libro_form.html", libro=request.form, autores=autores)

        conn.execute(
            "UPDATE libros SET titulo=?, autor_id=?, categoria=?, stock=? WHERE id=?",
            (titulo, autor_id, categoria, stock, id),
        )
        conn.commit()
        conn.close()
        flash("Libro actualizado correctamente.", "success")
        return redirect(url_for("listar_libros"))
    libro = conn.execute("SELECT * FROM libros WHERE id = ?", (id,)).fetchone()
    autores = conn.execute("SELECT * FROM autores ORDER BY nombre").fetchall()
    conn.close()
    if libro is None:
        abort(404)
    return render_template("libro_form.html", libro=libro, autores=autores)


@app.route("/libros/eliminar/<int:id>", methods=["POST"])
@login_required
def eliminar_libro(id):
    conn = get_db()
    conn.execute("DELETE FROM libros WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    flash("Libro eliminado.", "info")
    return redirect(url_for("listar_libros"))


# ---------------------------------------------------------------
# CRUD: USUARIOS (estudiantes)  (lectura: ambos / escritura: administrador)
# ---------------------------------------------------------------
@app.route("/usuarios")
@login_required
def listar_usuarios():
    conn = get_db()
    usuarios = conn.execute("SELECT * FROM usuarios ORDER BY nombre").fetchall()
    conn.close()
    return render_template("usuarios.html", usuarios=usuarios)


@app.route("/usuarios/nuevo", methods=["GET", "POST"])
@role_required("administrador")
def crear_usuario():
    if request.method == "POST":
        nombre = request.form.get("nombre", "").strip()
        curso = request.form.get("curso", "").strip()

        errores = validar_texto(nombre, "Nombre", maximo=100)
        errores += validar_texto(curso, "Curso", maximo=40, obligatorio=False)

        if errores:
            for e in errores:
                flash(e, "danger")
            return render_template("usuario_form.html", usuario=request.form)

        conn = get_db()
        conn.execute(
            "INSERT INTO usuarios (nombre, curso) VALUES (?, ?)", (nombre, curso)
        )
        conn.commit()
        conn.close()
        flash("Usuario agregado correctamente.", "success")
        return redirect(url_for("listar_usuarios"))
    return render_template("usuario_form.html", usuario=None)


@app.route("/usuarios/editar/<int:id>", methods=["GET", "POST"])
@role_required("administrador")
def editar_usuario(id):
    conn = get_db()
    if request.method == "POST":
        nombre = request.form.get("nombre", "").strip()
        curso = request.form.get("curso", "").strip()

        errores = validar_texto(nombre, "Nombre", maximo=100)
        errores += validar_texto(curso, "Curso", maximo=40, obligatorio=False)

        if errores:
            conn.close()
            for e in errores:
                flash(e, "danger")
            return render_template("usuario_form.html", usuario=request.form)

        conn.execute(
            "UPDATE usuarios SET nombre=?, curso=? WHERE id=?", (nombre, curso, id)
        )
        conn.commit()
        conn.close()
        flash("Usuario actualizado correctamente.", "success")
        return redirect(url_for("listar_usuarios"))
    usuario = conn.execute("SELECT * FROM usuarios WHERE id = ?", (id,)).fetchone()
    conn.close()
    if usuario is None:
        abort(404)
    return render_template("usuario_form.html", usuario=usuario)


@app.route("/usuarios/eliminar/<int:id>", methods=["POST"])
@role_required("administrador")
def eliminar_usuario(id):
    conn = get_db()
    conn.execute("DELETE FROM usuarios WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    flash("Usuario eliminado.", "info")
    return redirect(url_for("listar_usuarios"))


# ---------------------------------------------------------------
# CRUD: PRESTAMOS (ambos roles)
# ---------------------------------------------------------------
@app.route("/prestamos")
@login_required
def listar_prestamos():
    conn = get_db()
    prestamos = conn.execute(
        """SELECT prestamos.id, libros.titulo AS libro_titulo,
                  usuarios.nombre AS usuario_nombre,
                  prestamos.fecha_prestamo, prestamos.fecha_devolucion,
                  prestamos.estado
           FROM prestamos
           JOIN libros ON prestamos.libro_id = libros.id
           JOIN usuarios ON prestamos.usuario_id = usuarios.id
           ORDER BY prestamos.fecha_prestamo DESC"""
    ).fetchall()
    conn.close()
    return render_template("prestamos.html", prestamos=prestamos)


@app.route("/prestamos/nuevo", methods=["GET", "POST"])
@login_required
def crear_prestamo():
    conn = get_db()
    if request.method == "POST":
        libro_id = request.form.get("libro_id", "")
        usuario_id = request.form.get("usuario_id", "")
        fecha_prestamo = date.today().isoformat()

        libro = conn.execute("SELECT id FROM libros WHERE id = ?", (libro_id,)).fetchone()
        usuario = conn.execute("SELECT id FROM usuarios WHERE id = ?", (usuario_id,)).fetchone()

        errores = []
        if libro is None:
            errores.append("Debes seleccionar un libro válido.")
        if usuario is None:
            errores.append("Debes seleccionar un usuario válido.")

        if errores:
            libros = conn.execute("SELECT * FROM libros WHERE stock > 0 ORDER BY titulo").fetchall()
            usuarios = conn.execute("SELECT * FROM usuarios ORDER BY nombre").fetchall()
            conn.close()
            for e in errores:
                flash(e, "danger")
            return render_template("prestamo_form.html", libros=libros, usuarios=usuarios)

        # Verifica que haya stock disponible antes de prestar
        libro_stock = conn.execute(
            "SELECT stock FROM libros WHERE id = ?", (libro_id,)
        ).fetchone()

        if libro_stock["stock"] <= 0:
            flash("No hay stock disponible para ese libro.", "danger")
            conn.close()
            return redirect(url_for("crear_prestamo"))

        conn.execute(
            """INSERT INTO prestamos (libro_id, usuario_id, fecha_prestamo, estado)
               VALUES (?, ?, ?, 'Prestado')""",
            (libro_id, usuario_id, fecha_prestamo),
        )
        conn.execute(
            "UPDATE libros SET stock = stock - 1 WHERE id = ?", (libro_id,)
        )
        conn.commit()
        conn.close()
        flash("Préstamo registrado correctamente.", "success")
        return redirect(url_for("listar_prestamos"))

    libros = conn.execute("SELECT * FROM libros WHERE stock > 0 ORDER BY titulo").fetchall()
    usuarios = conn.execute("SELECT * FROM usuarios ORDER BY nombre").fetchall()
    conn.close()
    return render_template("prestamo_form.html", libros=libros, usuarios=usuarios)


@app.route("/prestamos/devolver/<int:id>", methods=["POST"])
@login_required
def devolver_prestamo(id):
    conn = get_db()
    prestamo = conn.execute("SELECT * FROM prestamos WHERE id = ?", (id,)).fetchone()
    if prestamo and prestamo["estado"] == "Prestado":
        conn.execute(
            "UPDATE prestamos SET estado='Devuelto', fecha_devolucion=? WHERE id=?",
            (date.today().isoformat(), id),
        )
        conn.execute(
            "UPDATE libros SET stock = stock + 1 WHERE id = ?", (prestamo["libro_id"],)
        )
        conn.commit()
        flash("Devolución registrada correctamente.", "success")
    conn.close()
    return redirect(url_for("listar_prestamos"))


@app.route("/prestamos/eliminar/<int:id>", methods=["POST"])
@login_required
def eliminar_prestamo(id):
    conn = get_db()
    conn.execute("DELETE FROM prestamos WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    flash("Préstamo eliminado.", "info")
    return redirect(url_for("listar_prestamos"))


# ---------------------------------------------------------------
# CRUD: CUENTAS DEL SISTEMA (solo administrador)
# ---------------------------------------------------------------
PATRON_USUARIO = re.compile(r"^[a-zA-Z0-9_.]{3,30}$")


@app.route("/cuentas")
@role_required("administrador")
def listar_cuentas():
    conn = get_db()
    cuentas = conn.execute("SELECT id, nombre_completo, usuario, rol FROM cuentas ORDER BY nombre_completo").fetchall()
    conn.close()
    return render_template("cuentas.html", cuentas=cuentas)


@app.route("/cuentas/nueva", methods=["GET", "POST"])
@role_required("administrador")
def crear_cuenta():
    if request.method == "POST":
        nombre_completo = request.form.get("nombre_completo", "").strip()
        usuario = request.form.get("usuario", "").strip()
        password = request.form.get("password", "")
        rol = request.form.get("rol", "")

        errores = validar_texto(nombre_completo, "Nombre completo", maximo=100)
        if not PATRON_USUARIO.match(usuario):
            errores.append("El nombre de usuario debe tener entre 3 y 30 caracteres (letras, números, punto o guion bajo).")
        if len(password) < 6:
            errores.append("La contraseña debe tener al menos 6 caracteres.")
        if rol not in ("administrador", "bibliotecario"):
            errores.append("Debes seleccionar un rol válido.")

        conn = get_db()
        if not errores:
            existe = conn.execute("SELECT id FROM cuentas WHERE usuario = ?", (usuario,)).fetchone()
            if existe:
                errores.append("Ese nombre de usuario ya está en uso.")

        if errores:
            conn.close()
            for e in errores:
                flash(e, "danger")
            return render_template("cuenta_form.html", cuenta=request.form)

        conn.execute(
            "INSERT INTO cuentas (nombre_completo, usuario, password_hash, rol) VALUES (?, ?, ?, ?)",
            (nombre_completo, usuario, generate_password_hash(password), rol),
        )
        conn.commit()
        conn.close()
        flash("Cuenta creada correctamente.", "success")
        return redirect(url_for("listar_cuentas"))
    return render_template("cuenta_form.html", cuenta=None)


@app.route("/cuentas/editar/<int:id>", methods=["GET", "POST"])
@role_required("administrador")
def editar_cuenta(id):
    conn = get_db()
    if request.method == "POST":
        nombre_completo = request.form.get("nombre_completo", "").strip()
        usuario = request.form.get("usuario", "").strip()
        password = request.form.get("password", "")
        rol = request.form.get("rol", "")

        errores = validar_texto(nombre_completo, "Nombre completo", maximo=100)
        if not PATRON_USUARIO.match(usuario):
            errores.append("El nombre de usuario debe tener entre 3 y 30 caracteres (letras, números, punto o guion bajo).")
        if password and len(password) < 6:
            errores.append("La contraseña debe tener al menos 6 caracteres (o déjala en blanco para no cambiarla).")
        if rol not in ("administrador", "bibliotecario"):
            errores.append("Debes seleccionar un rol válido.")

        duplicado = conn.execute(
            "SELECT id FROM cuentas WHERE usuario = ? AND id != ?", (usuario, id)
        ).fetchone()
        if duplicado:
            errores.append("Ese nombre de usuario ya está en uso.")

        if errores:
            conn.close()
            for e in errores:
                flash(e, "danger")
            return render_template("cuenta_form.html", cuenta=request.form)

        if password:
            conn.execute(
                "UPDATE cuentas SET nombre_completo=?, usuario=?, password_hash=?, rol=? WHERE id=?",
                (nombre_completo, usuario, generate_password_hash(password), rol, id),
            )
        else:
            conn.execute(
                "UPDATE cuentas SET nombre_completo=?, usuario=?, rol=? WHERE id=?",
                (nombre_completo, usuario, rol, id),
            )
        conn.commit()
        conn.close()
        flash("Cuenta actualizada correctamente.", "success")
        return redirect(url_for("listar_cuentas"))

    cuenta = conn.execute("SELECT * FROM cuentas WHERE id = ?", (id,)).fetchone()
    conn.close()
    if cuenta is None:
        abort(404)
    return render_template("cuenta_form.html", cuenta=cuenta)


@app.route("/cuentas/eliminar/<int:id>", methods=["POST"])
@role_required("administrador")
def eliminar_cuenta(id):
    if id == session.get("cuenta_id"):
        flash("No puedes eliminar tu propia cuenta mientras tienes la sesión abierta.", "danger")
        return redirect(url_for("listar_cuentas"))
    conn = get_db()
    conn.execute("DELETE FROM cuentas WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    flash("Cuenta eliminada.", "info")
    return redirect(url_for("listar_cuentas"))


# ---------------------------------------------------------------
# MANEJO DE ERRORES: no exponer detalles tecnicos al usuario final
# ---------------------------------------------------------------
@app.errorhandler(403)
def error_403(e):
    return render_template("error.html", codigo=403, mensaje="No tienes permiso para acceder a esta página."), 403


@app.errorhandler(404)
def error_404(e):
    return render_template("error.html", codigo=404, mensaje="La página que buscas no existe."), 404


@app.errorhandler(500)
def error_500(e):
    return render_template("error.html", codigo=500, mensaje="Ocurrió un error interno. Inténtalo nuevamente más tarde."), 500


if __name__ == "__main__":
    app.run(debug=True)
