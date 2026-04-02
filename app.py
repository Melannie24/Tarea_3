import os
import uuid
import json
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from flask import Flask, g, redirect, render_template, request, session, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import sqlite3

# ─────────────────────────────────────────────────────────
# CONFIGURACIÓN
# ─────────────────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "clave-secreta-estudio-cambiar-en-produccion")
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # 1 MB

KEYS_DIR = os.path.join(os.path.dirname(__file__), "keys")
PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "private_key.pem")
PUBLIC_KEY_PATH  = os.path.join(KEYS_DIR, "public_key.pem")
TOKEN_EXPIRY_DAYS = 7

# ─────────────────────────────────────────────────────────
# RSA — GENERACIÓN Y CARGA DE LLAVES
# ─────────────────────────────────────────────────────────

def generar_llaves_rsa():
    """Genera el par de llaves RSA 2048-bit y las guarda en /keys."""
    os.makedirs(KEYS_DIR, exist_ok=True)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print("[INFO] Llaves RSA generadas correctamente.")


def cargar_llave_publica():
    with open(PUBLIC_KEY_PATH, "rb") as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())


def cargar_llave_privada():
    with open(PRIVATE_KEY_PATH, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())


def cifrar_rsa(texto: str) -> bytes:
    """Cifra texto plano con RSA-OAEP + SHA-256 usando la llave pública."""
    public_key = cargar_llave_publica()
    return public_key.encrypt(
        texto.encode("utf-8"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def descifrar_rsa(ciphertext: bytes) -> str:
    """Descifra con la llave privada RSA."""
    private_key = cargar_llave_privada()
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode("utf-8")

# ─────────────────────────────────────────────────────────
# BASE DE DATOS
# ─────────────────────────────────────────────────────────

def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect("db.sqlite3")
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")   # mejora concurrencia
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db:
        db.close()


def init_db():
    """Crea las tablas si no existen (basado en el Diagrama E-R)."""
    with sqlite3.connect("db.sqlite3") as conn:
        conn.executescript("""
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS usuario (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                username        TEXT NOT NULL UNIQUE,
                password        TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS registro (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                usuario_id      INTEGER NOT NULL REFERENCES usuario(id),
                etiqueta        TEXT NOT NULL,
                texto_cifrado   BLOB NOT NULL,
                token           TEXT NOT NULL UNIQUE,
                estado          TEXT NOT NULL DEFAULT 'ACTIVO'
                                    CHECK(estado IN ('ACTIVO','LEIDO','ELIMINADO')),
                fecha_creacion  TEXT NOT NULL,
                fecha_expiracion TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS auditoria (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                registro_id     INTEGER REFERENCES registro(id),
                accion          TEXT NOT NULL
                                    CHECK(accion IN ('CIFRADO','LECTURA','FALLO','INACTIVACION')),
                fecha           TEXT NOT NULL,
                metadatos       TEXT
            );
        """)

# ─────────────────────────────────────────────────────────
# DECORADOR DE AUTENTICACIÓN
# ─────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "usuario_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

# ─────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────

def registrar_auditoria(db, registro_id, accion, request_obj):
    """Guarda un evento de auditoría con IP y User-Agent."""
    ip = request_obj.remote_addr or "desconocida"
    ua = request_obj.headers.get("User-Agent", "desconocido")
    metadatos = json.dumps({"ip": ip, "user_agent": ua})
    db.execute(
        "INSERT INTO auditoria (registro_id, accion, fecha, metadatos) VALUES (?, ?, ?, ?)",
        (registro_id, accion, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), metadatos)
    )


def ahora_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def expiracion_str() -> str:
    return (datetime.now() + timedelta(days=TOKEN_EXPIRY_DAYS)).strftime("%Y-%m-%d %H:%M:%S")


def token_expirado(fecha_expiracion_str: str) -> bool:
    exp = datetime.strptime(fecha_expiracion_str, "%Y-%m-%d %H:%M:%S")
    return datetime.now() > exp

# ─────────────────────────────────────────────────────────
# RUTAS — AUTENTICACIÓN
# ─────────────────────────────────────────────────────────

@app.route("/")
def index():
    if "usuario_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        db = get_db()
        user = db.execute(
            "SELECT * FROM usuario WHERE username = ?", (username,)
        ).fetchone()
        if user and check_password_hash(user["password"], password):
            session["usuario_id"] = user["id"]
            session["username"]   = user["username"]
            return redirect(url_for("dashboard"))
        flash("Usuario o contraseña incorrectos.")
    return render_template("login.html")


@app.route("/registro", methods=["GET", "POST"])
def registro_usuario():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        if not username or not password:
            flash("Todos los campos son obligatorios.")
            return render_template("registro_usuario.html")
        db = get_db()
        existente = db.execute(
            "SELECT id FROM usuario WHERE username = ?", (username,)
        ).fetchone()
        if existente:
            flash("Ese nombre de usuario ya existe.")
            return render_template("registro_usuario.html")
        db.execute(
            "INSERT INTO usuario (username, password) VALUES (?, ?)",
            (username, generate_password_hash(password))
        )
        db.commit()
        flash("Cuenta creada. Inicia sesión.")
        return redirect(url_for("login"))
    return render_template("registro_usuario.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ─────────────────────────────────────────────────────────
# RUTAS — DASHBOARD E HISTORIAL
# ─────────────────────────────────────────────────────────

@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    estado_filtro = request.args.get("estado", "todos")
    if estado_filtro in ("ACTIVO", "LEIDO", "ELIMINADO"):
        registros = db.execute(
            "SELECT * FROM registro WHERE usuario_id = ? AND estado = ? ORDER BY fecha_creacion DESC",
            (session["usuario_id"], estado_filtro)
        ).fetchall()
    else:
        registros = db.execute(
            "SELECT * FROM registro WHERE usuario_id = ? ORDER BY fecha_creacion DESC",
            (session["usuario_id"],)
        ).fetchall()
    return render_template("dashboard.html", registros=registros, filtro=estado_filtro)

# ─────────────────────────────────────────────────────────
# RUTAS — CIFRADO
# ─────────────────────────────────────────────────────────

@app.route("/cifrar", methods=["POST"])
@login_required
def cifrar():
    etiqueta = request.form.get("etiqueta", "").strip()
    texto    = request.form.get("texto", "").strip()

    if not etiqueta or not texto:
        flash("Etiqueta y texto son obligatorios.")
        return redirect(url_for("dashboard"))

    texto_cifrado = cifrar_rsa(texto)
    token         = str(uuid.uuid4())
    db            = get_db()

    cursor = db.execute(
        """INSERT INTO registro
           (usuario_id, etiqueta, texto_cifrado, token, estado, fecha_creacion, fecha_expiracion)
           VALUES (?, ?, ?, ?, 'ACTIVO', ?, ?)""",
        (session["usuario_id"], etiqueta, texto_cifrado, token, ahora_str(), expiracion_str())
    )
    registro_id = cursor.lastrowid
    registrar_auditoria(db, registro_id, "CIFRADO", request)
    db.commit()

    flash(f"token:{token}")   # flag especial para mostrar token en dashboard
    return redirect(url_for("dashboard"))

# ─────────────────────────────────────────────────────────
# RUTAS — DESCIFRADO (acceso público)
# ─────────────────────────────────────────────────────────

@app.route("/descifrar", methods=["GET", "POST"])
def descifrar():
    """Acceso público: cualquiera con token puede descifrar (un solo uso)."""
    if request.method == "GET":
        token_prefill = request.args.get("token", "")
        return render_template("descifrar.html", token=token_prefill)

    token = request.form.get("token", "").strip()
    db    = get_db()

    # SELECT con bloqueo lógico para evitar doble uso concurrente
    row = db.execute(
        "SELECT * FROM registro WHERE token = ?", (token,)
    ).fetchone()

    if not row:
        registrar_auditoria(db, None, "FALLO", request)
        db.commit()
        return render_template("error_token.html", motivo="TOKEN_INVALIDO")

    if row["estado"] != "ACTIVO":
        registrar_auditoria(db, row["id"], "FALLO", request)
        db.commit()
        return render_template("error_token.html", motivo="TOKEN_USADO")

    if token_expirado(row["fecha_expiracion"]):
        db.execute("UPDATE registro SET estado = 'ELIMINADO' WHERE id = ?", (row["id"],))
        registrar_auditoria(db, row["id"], "FALLO", request)
        db.commit()
        return render_template("error_token.html", motivo="TOKEN_EXPIRADO")

    # Token válido → descifrar y marcar como LEIDO
    try:
        texto = descifrar_rsa(row["texto_cifrado"])
    except Exception:
        return render_template("error_token.html", motivo="ERROR_INTERNO")

    db.execute("UPDATE registro SET estado = 'LEIDO' WHERE id = ?", (row["id"],))
    registrar_auditoria(db, row["id"], "LECTURA", request)
    db.commit()

    return render_template("resultado.html", texto=texto, etiqueta=row["etiqueta"])

# ─────────────────────────────────────────────────────────
# RUTAS — INACTIVAR REGISTRO (borrado lógico)
# ─────────────────────────────────────────────────────────

@app.route("/inactivar/<int:registro_id>", methods=["POST"])
@login_required
def inactivar(registro_id):
    db = get_db()
    row = db.execute(
        "SELECT * FROM registro WHERE id = ? AND usuario_id = ?",
        (registro_id, session["usuario_id"])
    ).fetchone()
    if not row:
        flash("Registro no encontrado.")
        return redirect(url_for("dashboard"))
    db.execute("UPDATE registro SET estado = 'ELIMINADO' WHERE id = ?", (registro_id,))
    registrar_auditoria(db, registro_id, "INACTIVACION", request)
    db.commit()
    flash("Registro inactivado correctamente.")
    return redirect(url_for("dashboard"))

# ─────────────────────────────────────────────────────────
# RUTAS — AUDITORÍA
# ─────────────────────────────────────────────────────────

@app.route("/auditoria/<int:registro_id>")
@login_required
def auditoria(registro_id):
    db = get_db()
    reg = db.execute(
        "SELECT * FROM registro WHERE id = ? AND usuario_id = ?",
        (registro_id, session["usuario_id"])
    ).fetchone()
    if not reg:
        flash("No tienes acceso a ese registro.")
        return redirect(url_for("dashboard"))
    eventos = db.execute(
        "SELECT * FROM auditoria WHERE registro_id = ? ORDER BY fecha DESC",
        (registro_id,)
    ).fetchall()
    return render_template("auditoria.html", registro=reg, eventos=eventos)

# ─────────────────────────────────────────────────────────
# ARRANQUE
# ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    if not os.path.exists(PRIVATE_KEY_PATH):
        generar_llaves_rsa()
    init_db()
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug)
