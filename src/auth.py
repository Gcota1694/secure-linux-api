import logging
import jwt
import time
import re

try:
    import pwd
    HAS_PWD = True
except ImportError:
    HAS_PWD = False

from functools import wraps
from flask import Blueprint, request, jsonify, current_app, g

logger = logging.getLogger(__name__)
auth_bp = Blueprint('auth', __name__)


def _is_safe_username(username: str) -> bool:
    pattern = r'^[a-zA-Z_][a-zA-Z0-9_.-]{0,31}$'
    return bool(re.match(pattern, username))


def _pam_authenticate(username: str, password: str) -> bool:
    try:
        import pam
        p = pam.pam()
        result = p.authenticate(username, password, service='login')
        if result:
            logger.info(f"PAM autenticación exitosa: {username}")
        else:
            logger.warning(f"PAM autenticación fallida: {username}")
        return result
    except ImportError:
        logger.error("python-pam no instalado")
        raise RuntimeError("Módulo PAM no disponible")
    except Exception as e:
        logger.error(f"Error PAM: {e}")
        return False


def _dev_authenticate(username: str, password: str) -> bool:
    if HAS_PWD:
        try:
            pwd.getpwnam(username)
        except KeyError:
            logger.warning(f"Usuario '{username}' no existe en el sistema")
            return False
    test_password = current_app.config.get('DEV_PASSWORD', 'devpassword')
    return password == test_password


def authenticate_linux_user(username: str, password: str) -> bool:
    if not username or not password:
        return False
    if not _is_safe_username(username):
        logger.warning(f"Formato de usuario inválido: {username!r}")
        return False
    allowed_users = current_app.config.get('ALLOWED_USERS', [])
    if allowed_users and username not in allowed_users:
        logger.warning(f"Usuario '{username}' no está en la lista permitida")
        return False
    if current_app.config.get('USE_PAM_AUTH', True):
        return _pam_authenticate(username, password)
    else:
        logger.warning("PAM desactivado — usando modo desarrollo")
        return _dev_authenticate(username, password)


def generate_token(username: str) -> str:
    now = int(time.time())
    expires = current_app.config['JWT_ACCESS_TOKEN_EXPIRES']
    exp = now + int(expires.total_seconds())
    payload = {'sub': username, 'iat': now, 'exp': exp, 'type': 'access'}
    return jwt.encode(
        payload,
        current_app.config['JWT_SECRET_KEY'],
        algorithm=current_app.config.get('JWT_ALGORITHM', 'HS256')
    )


def verify_token(token: str):
    try:
        return jwt.decode(
            token,
            current_app.config['JWT_SECRET_KEY'],
            algorithms=[current_app.config.get('JWT_ALGORITHM', 'HS256')]
        )
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({"error": "Unauthorized", "message": "Se requiere token Bearer"}), 401
        token = auth_header.split(' ', 1)[1].strip()
        if not token:
            return jsonify({"error": "Unauthorized", "message": "Token faltante"}), 401
        payload = verify_token(token)
        if not payload:
            return jsonify({"error": "Unauthorized", "message": "Token inválido o expirado"}), 401
        g.current_user = payload['sub']
        return f(*args, **kwargs)
    return decorated


@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Bad Request", "message": "Se requiere body JSON"}), 400

    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({"error": "Bad Request", "message": "username y password son requeridos"}), 400

    logger.info(f"Intento de login: '{username}' desde {request.remote_addr}")

    try:
        if not authenticate_linux_user(username, password):
            time.sleep(0.5)
            return jsonify({"error": "Unauthorized", "message": "Credenciales inválidas"}), 401
    except RuntimeError as e:
        return jsonify({"error": "Service Unavailable", "message": str(e)}), 503

    token = generate_token(username)
    expires_in = int(current_app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds())

    logger.info(f"Login exitoso: '{username}'")
    return jsonify({
        "token": token,
        "token_type": "Bearer",
        "expires_in": expires_in,
        "username": username
    }), 200


@auth_bp.route('/verify', methods=['GET'])
@require_auth
def verify():
    return jsonify({"valid": True, "username": g.current_user}), 200