from flask import Flask, render_template, g
from app.config import Config, IS_PRODUCTION
from app.database import init_db
from app.security import get_current_user
from flask_wtf.csrf import CSRFProtect
def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    csrf = CSRFProtect()
    csrf.init_app(app)

    # Initialize database tables and directories
    with app.app_context():
        init_db()
        if IS_PRODUCTION:
            from bootstrap_admin import bootstrap_admin_from_environment
            bootstrap_admin_from_environment()

    # Register Blueprints
    from app.routes.auth_routes import auth_bp
    from app.routes.doc_routes import doc_bp
    from app.routes.admin_routes import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(doc_bp)
    app.register_blueprint(admin_bp)

    # Inject current user into all Jinja templates
    @app.context_processor
    def inject_user():
        return {
            "current_user": get_current_user(),
            "show_demo_accounts": app.config["SHOW_DEMO_ACCOUNTS"],
        }

    # Security Headers Middleware
    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' https://cdn.tailwindcss.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
            "font-src 'self' data:; "
            "img-src 'self' data:;"
        )
        return response

    # Standardized Error Handlers
    @app.errorhandler(403)
    def forbidden(e):
        return render_template("errors/403.html"), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template("errors/404.html"), 404

    @app.errorhandler(401)
    def unauthorized(e):
        return render_template("errors/401.html"), 401

    @app.errorhandler(500)
    def server_error(e):
        return render_template("errors/500.html"), 500

    return app
