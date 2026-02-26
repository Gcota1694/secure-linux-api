import logging
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, current_app, g
from .auth import require_auth
from .executor import SecureCommandExecutor, CommandNotAllowedError, SecurityError

logger = logging.getLogger(__name__)
system_bp = Blueprint('system', __name__)


def get_executor():
    return SecureCommandExecutor(
        allowed_commands=current_app.config['ALLOWED_COMMANDS'],
        timeout=current_app.config.get('COMMAND_TIMEOUT', 30),
        max_output=current_app.config.get('MAX_OUTPUT_SIZE', 1024 * 1024)
    )


@system_bp.route('/execute', methods=['POST'])
@require_auth
def execute_command():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Bad Request", "message": "Se requiere body JSON"}), 400

    command = data.get('command')
    params = data.get('params', [])

    if not command or not isinstance(command, str):
        return jsonify({"error": "Bad Request", "message": "'command' debe ser un string"}), 400
    if not isinstance(params, list):
        return jsonify({"error": "Bad Request", "message": "'params' debe ser un array"}), 400
    if len(params) > 10:
        return jsonify({"error": "Bad Request", "message": "Demasiados parámetros (máx 10)"}), 400

    try:
        result = get_executor().execute(
            command=command.strip().lower(),
            params=params,
            requesting_user=g.current_user
        )
        return jsonify({
            "success": result.success,
            "command": result.command,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.exit_code,
            "execution_time_ms": result.execution_time_ms,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "executed_by": g.current_user
        }), 200

    except CommandNotAllowedError as e:
        return jsonify({
            "error": "Forbidden",
            "message": str(e),
            "available_commands": list(current_app.config['ALLOWED_COMMANDS'].keys())
        }), 403

    except SecurityError as e:
        logger.warning(f"Violación de seguridad por '{g.current_user}': {e}")
        return jsonify({"error": "Forbidden", "message": f"Violación de seguridad: {e}"}), 403

    except Exception as e:
        logger.error(f"Error inesperado: {e}", exc_info=True)
        return jsonify({"error": "Internal Server Error", "message": "Fallo en ejecución"}), 500


@system_bp.route('/commands', methods=['GET'])
@require_auth
def list_commands():
    allowed = current_app.config['ALLOWED_COMMANDS']
    commands_info = {
        name: {
            "description": cfg.get('description', ''),
            "allowed_flags": cfg.get('allow_flags', [])
        }
        for name, cfg in allowed.items()
    }
    return jsonify({"commands": commands_info, "total": len(commands_info)}), 200


@system_bp.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        "status": "healthy",
        "service": "secure-linux-api",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }), 200