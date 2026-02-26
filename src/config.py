import os
from datetime import timedelta


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key'
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'dev-jwt-secret'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_ALGORITHM = 'HS256'
    LOG_FILE = os.environ.get('LOG_FILE', 'api.log')
    COMMAND_TIMEOUT = int(os.environ.get('COMMAND_TIMEOUT', 30))
    MAX_OUTPUT_SIZE = int(os.environ.get('MAX_OUTPUT_SIZE', 1024 * 1024))
    USE_PAM_AUTH = os.environ.get('USE_PAM_AUTH', 'true').lower() == 'true'
    ALLOWED_USERS = [u.strip() for u in os.environ.get('ALLOWED_USERS', '').split(',') if u.strip()]

    ALLOWED_COMMANDS = {
        "uptime": {
            "description": "Muestra cuánto tiempo lleva corriendo el sistema",
            "binary": "/usr/bin/uptime",
            "allow_flags": ["-p", "-s"]
        },
        "whoami": {
            "description": "Muestra el usuario actual",
            "binary": "/usr/bin/whoami",
            "allow_flags": []
        },
        "hostname": {
            "description": "Muestra el nombre del servidor",
            "binary": "/bin/hostname",
            "allow_flags": ["-f", "-i", "-s"]
        },
        "date": {
            "description": "Muestra la fecha y hora actual",
            "binary": "/bin/date",
            "allow_flags": ["-u", "-R"]
        },
        "df": {
            "description": "Muestra el espacio en disco",
            "binary": "/bin/df",
            "allow_flags": ["-h", "-H", "-T", "-a"]
        },
        "free": {
            "description": "Muestra el uso de memoria RAM",
            "binary": "/usr/bin/free",
            "allow_flags": ["-h", "-m", "-g", "-b", "-k"]
        },
        "uname": {
            "description": "Muestra información del sistema",
            "binary": "/bin/uname",
            "allow_flags": ["-a", "-s", "-r", "-m"]
        },
        "ps": {
            "description": "Muestra los procesos activos",
            "binary": "/bin/ps",
            "allow_flags": ["aux", "u", "-u", "f"]
        },
        "id": {
            "description": "Muestra el ID del usuario actual",
            "binary": "/usr/bin/id",
            "allow_flags": ["-u", "-g", "-G", "-n"]
        },
        "lscpu": {
            "description": "Muestra información del CPU",
            "binary": "/usr/bin/lscpu",
            "allow_flags": []
        },
        "systeminfo": {
    "description": "Show system information (Windows)",
    "binary": "C:\\Windows\\System32\\systeminfo.exe",
    "allowed_params": [],
    "allow_flags": []
    }
    }


class DevelopmentConfig(Config):
    DEBUG = True
    USE_PAM_AUTH = False
    DEV_PASSWORD = 'devpassword'


class ProductionConfig(Config):
    DEBUG = False
    USE_PAM_AUTH = True


class TestingConfig(Config):
    TESTING = True
    USE_PAM_AUTH = False
    DEV_PASSWORD = 'testpassword'


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}