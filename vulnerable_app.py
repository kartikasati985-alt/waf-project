from flask import Blueprint, jsonify, request


vulnerable_bp = Blueprint("vulnerable", __name__)


@vulnerable_bp.route("/")
def home():
    return jsonify(
        {
            "message": "Vulnerable test app behind WAF",
            "endpoints": ["/search?q=", "/comment", "/file?name=", "/run?cmd="],
        }
    )


@vulnerable_bp.route("/search")
def search():
    query = request.args.get("q", "")
    return jsonify({"result": f"Search result for: {query}"})


@vulnerable_bp.route("/comment", methods=["POST"])
def comment():
    data = request.get_json(silent=True) or {}
    message = data.get("message", "")
    return jsonify({"saved": True, "message": message})


@vulnerable_bp.route("/file")
def file_view():
    filename = request.args.get("name", "")
    return jsonify({"file": filename, "content": "demo content"})


@vulnerable_bp.route("/run")
def run_cmd():
    command = request.args.get("cmd", "")
    return jsonify({"executed": command, "status": "simulated"})


@vulnerable_bp.route("/xml", methods=["POST"])
def xml_upload():
    xml_data = request.get_data(as_text=True)
    return jsonify({"received": len(xml_data)})
