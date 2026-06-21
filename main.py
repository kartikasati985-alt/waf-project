from flask import Flask

from config import DEFAULT_CONFIG
from dashboard import create_dashboard_blueprint
from logger import WAFLogger
from vulnerable_app import vulnerable_bp
from waf_engine import WAFEngine


def create_app(db_path="waf_logs.db"):
    app = Flask(__name__)
    waf_logger = WAFLogger(db_path=db_path)
    WAFEngine(app=app, config=DEFAULT_CONFIG, logger=waf_logger)
    app.register_blueprint(vulnerable_bp)
    app.register_blueprint(create_dashboard_blueprint(waf_logger))
    return app


if __name__ == "__main__":
    application = create_app()
    application.run(host="0.0.0.0", port=5000, debug=False)
