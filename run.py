import os
from src import create_app
from src.config import config

env = os.environ.get('FLASK_ENV', 'development')
app = create_app(config.get(env, config['default']))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    host = os.environ.get('HOST', '0.0.0.0')
    print(f"Iniciando API en modo '{env}' en {host}:{port}")
    app.run(host=host, port=port, debug=(env == 'development'))