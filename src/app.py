from flask import Flask
import logging
import sys
from .routes import system_bp
from .auth import auth_bp
from .config import Config


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        handlers=[logging.StreamHandler(sys.stdout)]
    )

    try:
        from flask_limiter import Limiter
        from flask_limiter.util import get_remote_address
        limiter = Limiter(get_remote_address, app=app,
                          default_limits=["100 per hour", "20 per minute"],
                          storage_uri="memory://")
        limiter.limit("30 per minute")(system_bp)
        app.logger.info("Rate limiting activado")
    except ImportError:
        app.logger.warning("flask-limiter no instalado — rate limiting desactivado")

    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(system_bp, url_prefix='/system')

    @app.errorhandler(401)
    def unauthorized(e):
        return {"error": "Unauthorized"}, 401

    @app.errorhandler(404)
    def not_found(e):
        return {"error": "Not Found"}, 404

    @app.errorhandler(500)
    def internal_error(e):
        return {"error": "Internal Server Error"}, 500

    return app