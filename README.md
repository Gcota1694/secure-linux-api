# 🔐 Secure Linux Command Execution API

API REST desarrollada en Python/Flask que permite ejecutar comandos Linux **preautorizados** en el servidor, implementando controles estrictos de seguridad para prevenir Command Injection, acceso no autorizado y ejecución arbitraria de código.

---

## 🏗️ Arquitectura de Seguridad

| Capa | Control Implementado |
|---|---|
| **Autenticación** | JWT + Linux PAM (usuarios reales del sistema) |
| **Autorización** | Whitelist de comandos — solo los explícitamente permitidos |
| **Validación de entrada** | Detección de caracteres peligrosos y patrones de inyección |
| **Ejecución** | `shell=False` siempre, rutas absolutas de binarios, entorno limpio |
| **Recursos** | Límites de CPU, memoria, file descriptors y procesos via `setrlimit` |
| **Rate Limiting** | Límites por IP en todos los endpoints |
| **Privilegios** | Usuario Linux limitado (principio de menor privilegio) |
| **Output** | Truncamiento para prevenir exfiltración de datos |

---

## 📁 Estructura del Proyecto

```
secure-linux-api/
├── src/
│   ├── __init__.py     # Inicialización del paquete
│   ├── app.py          # Factory de Flask
│   ├── config.py       # Whitelist de comandos y configuración
│   ├── auth.py         # JWT + autenticación PAM de Linux
│   ├── executor.py     # Ejecución segura con controles estrictos
│   └── routes.py       # Endpoints REST
├── tests/
│   └── test_api.py     # Suite de tests de seguridad
├── run.py              # Entry point
├── requirements.txt    # Dependencias Python
├── Dockerfile          # Contenedor para producción
├── .env.example        # Plantilla de variables de entorno
└── README.md
```

---

## ⚙️ Instalación y Configuración

### Requisitos
- Python 3.9+
- Linux (Ubuntu/Debian recomendado)
- Usuario Linux limitado (sin sudo)

### 1. Clonar el repositorio

```bash
git clone https://github.com/Gcota1694/secure-linux-api.git
cd secure-linux-api
```

### 2. Instalar dependencias del sistema

```bash
sudo apt update
sudo apt install -y python3-pip python3-venv libpam-dev
```

### 3. Crear entorno virtual e instalar dependencias Python

```bash
python3 -m venv venv
source venv/bin/activate
pip install flask flask-limiter PyJWT python-pam gunicorn
```

### 4. Configurar variables de entorno

```bash
cp .env.example .env
nano .env
```

Generar claves seguras:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
# Ejecutar 2 veces — una clave para SECRET_KEY y otra para JWT_SECRET_KEY
```

Contenido del `.env` para producción:

```env
FLASK_ENV=production
USE_PAM_AUTH=true
SECRET_KEY=tu_clave_generada_aqui
JWT_SECRET_KEY=tu_otra_clave_generada_aqui
COMMAND_TIMEOUT=30
MAX_OUTPUT_SIZE=1048576
ALLOWED_USERS=tu_usuario_linux
```

### 5. Ejecutar

```bash
export $(grep -v '^#' .env | xargs)
python3 run.py
```

---

## 🚀 Endpoints

### `POST /auth/login`
Autenticar un usuario Linux y obtener token JWT.

**Request:**
```json
{
  "username": "tu_usuario_linux",
  "password": "tu_password_linux"
}
```

**Response exitoso (200):**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "username": "tu_usuario_linux"
}
```

---

### `POST /system/execute`
Ejecutar un comando autorizado. Requiere `Authorization: Bearer <token>`.

**Request:**
```json
{
  "command": "uptime",
  "params": []
}
```

**Response exitoso (200):**
```json
{
  "success": true,
  "command": "uptime",
  "stdout": " 10:42:15 up 2 days, 3:14, 1 user, load average: 0.01, 0.05, 0.00",
  "stderr": "",
  "exit_code": 0,
  "execution_time_ms": 12.4,
  "timestamp": "2026-02-26T10:42:15.123Z",
  "executed_by": "tu_usuario"
}
```

**Con flags:**
```json
{
  "command": "free",
  "params": ["-h"]
}
```

---

### `GET /system/commands`
Listar todos los comandos autorizados. Requiere autenticación.

**Response (200):**
```json
{
  "commands": {
    "uptime": {
      "description": "Show how long the system has been running",
      "allowed_flags": ["-p", "-s"]
    }
  },
  "total": 12
}
```

---

### `GET /auth/verify`
Verificar que el token es válido. Requiere autenticación.

---

### `GET /system/health`
Health check público, no requiere autenticación.

**Response (200):**
```json
{
  "status": "healthy",
  "service": "secure-linux-api",
  "timestamp": "2026-02-26T10:42:15.123Z"
}
```

---

## 📋 Comandos Autorizados

| Comando | Descripción | Flags Permitidos |
|---|---|---|
| `uptime` | Tiempo de actividad del sistema | `-p`, `-s` |
| `whoami` | Usuario actual | — |
| `hostname` | Nombre del host | `-f`, `-i`, `-s` |
| `date` | Fecha y hora actual | `-u`, `-R` |
| `df` | Uso de espacio en disco | `-h`, `-H`, `-T`, `-a` |
| `free` | Uso de memoria RAM | `-h`, `-m`, `-g`, `-b`, `-k` |
| `uname` | Información del sistema | `-a`, `-s`, `-r`, `-m` |
| `ps` | Procesos activos | `aux`, `u`, `-u`, `f` |
| `id` | IDs de usuario y grupo | `-u`, `-g`, `-G`, `-n` |
| `env` | Variables de entorno | — |
| `lscpu` | Información de CPU | `-J`, `-e`, `-p` |
| `lsblk` | Dispositivos de bloque | `-f`, `-o`, `-J` |

---

## 🧪 Pruebas

### Ejecutar tests

```bash
pytest tests/ -v
```

### Pruebas manuales con curl

```bash
# 1. Health check
curl http://localhost:5000/system/health

# 2. Login
curl -X POST http://localhost:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "tu_usuario", "password": "tu_password"}'

# 3. Guardar token
TOKEN="pegar_token_aqui"

# 4. Ejecutar comando
curl -X POST http://localhost:5000/system/execute \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"command": "uptime", "params": []}'

# 5. Ver comandos disponibles
curl http://localhost:5000/system/commands \
  -H "Authorization: Bearer $TOKEN"
```

### Verificar que la seguridad funciona (deben devolver 403)

```bash
# Inyección con punto y coma
curl -X POST http://localhost:5000/system/execute \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"command": "uptime; cat /etc/passwd", "params": []}'

# Comando no autorizado
curl -X POST http://localhost:5000/system/execute \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"command": "ls", "params": []}'

# Sin token (debe devolver 401)
curl -X POST http://localhost:5000/system/execute \
  -H "Content-Type: application/json" \
  -d '{"command": "uptime", "params": []}'
```

---

## 🛡️ Modelo de Amenazas

| Amenaza | Mitigación |
|---|---|
| Command Injection | `shell=False`, validación de chars peligrosos, whitelist estricta |
| Path Traversal | Validación de parámetros, rutas absolutas de binarios |
| Escalada de privilegios | Usuario limitado, sin sudo, límites de recursos |
| Fuerza bruta | Rate limiting por IP, respuestas en tiempo constante |
| Robo de token | JWT con expiración de 1 hora, HTTPS en producción |
| DoS por comandos lentos | Timeout configurable, límites via `setrlimit` |
| Output excesivo | Truncamiento de salida a 1MB máximo |
| Manipulación de entorno | Entorno limpio pasado al subproceso |

---

## 🔧 Agregar Nuevos Comandos

Editar `src/config.py` y agregar en `ALLOWED_COMMANDS`:

```python
"iostat": {
    "description": "Report I/O statistics",
    "binary": "/usr/bin/iostat",
    "allowed_params": [],
    "allow_flags": ["-x", "-d", "-c"]
},
```

> ⚠️ **Nunca** usar wildcards para flags. Siempre enumerar explícitamente los permitidos.

---

## 🐳 Docker

```bash
docker build -t secure-linux-api .
docker run -p 5000:5000 \
  -e SECRET_KEY=tu_clave \
  -e JWT_SECRET_KEY=tu_jwt_clave \
  -e FLASK_ENV=production \
  secure-linux-api
```

---

## 📝 Notas de Producción

1. **Siempre usar HTTPS** — desplegar detrás de nginx o caddy con TLS
2. **Cambiar las claves** — nunca usar los valores de ejemplo
3. **Restringir usuarios** — usar `ALLOWED_USERS` para limitar quién puede autenticarse
4. **Firewall** — limitar acceso al puerto solo desde IPs confiables
5. **Logs** — monitorear `api.log` y `api-access.log` regularmente

---

## 📄 Licencia

MIT
