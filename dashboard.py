from flask import Blueprint, render_template


def create_dashboard_blueprint(waf_logger):
    dashboard_bp = Blueprint("dashboard", __name__, template_folder="templates")

    @dashboard_bp.route("/dashboard")
    def dashboard():
        stats = waf_logger.stats()
        events = waf_logger.recent_events(limit=50)
        return render_template("dashboard.html", stats=stats, events=events)

    return dashboard_bp
