import subprocess
import logging
import os
import re
from dataclasses import dataclass

try:
    import resource
    HAS_RESOURCE = True
except ImportError:
    HAS_RESOURCE = False

logger = logging.getLogger(__name__)


@dataclass
class CommandResult:
    success: bool
    stdout: str
    stderr: str
    exit_code: int
    command: str
    execution_time_ms: float


class SecurityError(Exception):
    pass


class CommandNotAllowedError(Exception):
    pass


class CommandValidator:
    DANGEROUS_CHARS = re.compile(r'[;&|`$()<>\\{}\[\]!#*?~]')
    INJECTION_PATTERNS = [
        re.compile(r'\.\./', re.IGNORECASE),
        re.compile(r'\/etc\/', re.IGNORECASE),
        re.compile(r'\beval\b', re.IGNORECASE),
        re.compile(r'\bexec\b', re.IGNORECASE),
        re.compile(r'\bbash\b', re.IGNORECASE),
        re.compile(r'\bsh\b', re.IGNORECASE),
        re.compile(r'\bsudo\b', re.IGNORECASE),
        re.compile(r'\bsu\b', re.IGNORECASE),
        re.compile(r'\brm\b', re.IGNORECASE),
        re.compile(r'\bwget\b', re.IGNORECASE),
        re.compile(r'\bcurl\b', re.IGNORECASE),
        re.compile(r'\bpython\b', re.IGNORECASE),
        re.compile(r'\bperl\b', re.IGNORECASE),
    ]

    @classmethod
    def validate_command_name(cls, command: str, allowed_commands: dict) -> dict:
        if not command or not isinstance(command, str):
            raise CommandNotAllowedError("El comando debe ser un string no vacío")
        command = command.strip().lower()
        if cls.DANGEROUS_CHARS.search(command):
            logger.warning(f"Caracteres peligrosos detectados en comando: {command!r}")
            raise SecurityError("El comando contiene caracteres inválidos")
        for pattern in cls.INJECTION_PATTERNS:
            if pattern.search(command):
                logger.warning(f"Patrón de inyección detectado: {command!r}")
                raise SecurityError("El comando contiene patrones prohibidos")
        if command not in allowed_commands:
            logger.warning(f"Comando no autorizado: {command!r}")
            raise CommandNotAllowedError(f"El comando '{command}' no está autorizado")
        return allowed_commands[command]

    @classmethod
    def validate_params(cls, params: list, command_config: dict) -> list:
        if not isinstance(params, list):
            raise SecurityError("Los parámetros deben ser una lista")
        if not params:
            return []
        allowed_flags = command_config.get('allow_flags', [])
        sanitized = []
        for param in params:
            if not isinstance(param, str):
                raise SecurityError("Todos los parámetros deben ser strings")
            param = param.strip()
            if not param:
                continue
            if cls.DANGEROUS_CHARS.search(param):
                raise SecurityError(f"Parámetro contiene caracteres inválidos: {param!r}")
            for pattern in cls.INJECTION_PATTERNS:
                if pattern.search(param):
                    raise SecurityError(f"Parámetro contiene patrón prohibido: {param!r}")
            if allowed_flags and param not in allowed_flags:
                raise SecurityError(
                    f"Parámetro '{param}' no permitido. Permitidos: {allowed_flags}")
            if len(param) > 50:
                raise SecurityError("Parámetro demasiado largo")
            sanitized.append(param)
        return sanitized


class SecureCommandExecutor:
    SAFE_ENV = {
        'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
        'LANG': 'en_US.UTF-8',
        'LC_ALL': 'en_US.UTF-8',
    }

    def __init__(self, allowed_commands, timeout=30, max_output=1024*1024):
        self.allowed_commands = allowed_commands
        self.timeout = timeout
        self.max_output = max_output
        self.validator = CommandValidator()

    def execute(self, command: str, params: list, requesting_user: str) -> CommandResult:
        import time
        cmd_config = self.validator.validate_command_name(command, self.allowed_commands)
        safe_params = self.validator.validate_params(params, cmd_config)
        binary_path = cmd_config.get('binary')
        if not binary_path:
            raise SecurityError(f"Ruta del binario no configurada para '{command}'")
        if not os.path.isfile(binary_path):
            raise SecurityError(f"Binario no encontrado: {binary_path}")
        if not os.access(binary_path, os.X_OK):
            raise SecurityError(f"Binario no ejecutable: {binary_path}")

        cmd_list = [binary_path] + safe_params
        logger.info(f"Ejecutando: user='{requesting_user}' cmd='{command}' params={safe_params}")
        start_time = time.time()

        # Solo aplicar límites de recursos en Linux
        preexec = self._set_resource_limits if HAS_RESOURCE else None

        try:
            process = subprocess.run(
                cmd_list,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                env=self.SAFE_ENV,
                shell=False,
                cwd=os.environ.get('TEMP', '/tmp'),
                preexec_fn=preexec,
            )
            elapsed_ms = (time.time() - start_time) * 1000
            stdout = process.stdout
            stderr = process.stderr
            if len(stdout) > self.max_output:
                stdout = stdout[:self.max_output] + "\n[SALIDA TRUNCADA]"
            logger.info(f"Completado: cmd='{command}' exit={process.returncode} time={elapsed_ms:.1f}ms")
            return CommandResult(
                success=process.returncode == 0,
                stdout=stdout.strip(),
                stderr=stderr.strip(),
                exit_code=process.returncode,
                command=command,
                execution_time_ms=round(elapsed_ms, 2)
            )
        except subprocess.TimeoutExpired:
            elapsed_ms = (time.time() - start_time) * 1000
            return CommandResult(
                success=False, stdout="",
                stderr=f"Comando expiró después de {self.timeout} segundos",
                exit_code=-1, command=command,
                execution_time_ms=round(elapsed_ms, 2)
            )
        except PermissionError as e:
            raise SecurityError(f"Permiso denegado: {e}")
        except FileNotFoundError:
            raise SecurityError("Binario del comando no encontrado")

    @staticmethod
    def _set_resource_limits():
        try:
            resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
            resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
            resource.setrlimit(resource.RLIMIT_NPROC, (10, 10))
            mem_limit = 64 * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (mem_limit, mem_limit))
        except Exception:
            pass