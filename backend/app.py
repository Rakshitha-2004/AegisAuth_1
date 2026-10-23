"""
AegisAuth: Context-Aware Zero-Trust Authentication & Threat Detection System
Main Flask Application Server
"""
import sys
import os
import mimetypes
from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS

mimetypes.init()
mimetypes.add_type("application/javascript", ".js")
mimetypes.add_type("text/javascript", ".js")
mimetypes.add_type("text/css", ".css")
mimetypes.add_type("image/svg+xml", ".svg")

from config import Config
from database.db import init_db, get_db_status
from routes.auth import auth_bp
from routes.soc import soc_bp
from routes.simulator import simulator_bp

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Enable CORS for frontend web client
    CORS(
        app,
        resources={r"/api/*": {"origins": "*"}},
        supports_credentials=True,
        methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization", "X-Requested-With", "X-Forwarded-For"]
    )

    # Initialize Database Connection & Security Indexes
    with app.app_context():
        init_db()

    # Register Blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(soc_bp)
    app.register_blueprint(simulator_bp)

    dist_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend", "dist"))

    @app.route("/", defaults={"path": ""})
    @app.route("/<path:path>")
    def serve_frontend(path):
        if path.startswith("api/"):
            return jsonify({"status": "error", "message": "API endpoint not found"}), 404
        target_path = os.path.join(dist_dir, path)
        if path and os.path.exists(target_path) and os.path.isfile(target_path):
            mimetype = None
            if path.endswith(".js"):
                mimetype = "application/javascript"
            elif path.endswith(".css"):
                mimetype = "text/css"
            elif path.endswith(".svg"):
                mimetype = "image/svg+xml"
            return send_from_directory(dist_dir, path, mimetype=mimetype)
        index_file = os.path.join(dist_dir, "index.html")
        if os.path.exists(index_file):
            return send_from_directory(dist_dir, "index.html")
        return jsonify({
            "service": "AegisAuth PDP Engine",
            "standard": "NIST SP 800-207 Zero-Trust Architecture",
            "version": "1.0.0",
            "status": "RUNNING"
        }), 200

    @app.route("/api/health")
    def health():
        db_stat = get_db_status()
        return jsonify({
            "status": "ONLINE" if db_stat.get("connected") else "DEGRADED",
            "database": db_stat,
            "security_engines": {
                "velocity_engine": "ACTIVE (Haversine Geodesic)",
                "fingerprint_engine": "ACTIVE (SHA-256 Hardware Entropy)",
                "rate_limiter": "ACTIVE (Sliding Window)",
                "pdp_engine": "ACTIVE (Adaptive Zero-Trust)"
            }
        }), 200

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"status": "error", "message": "The requested endpoint was not found on AegisAuth server."}), 404

    @app.errorhandler(500)
    def server_error(e):
        return jsonify({"status": "error", "message": "Internal Zero-Trust server error."}), 500

    return app

if __name__ == "__main__":
    app = create_app()
    port = int(os.environ.get("PORT", Config.PORT or 5000))
    print(f"\n=======================================================")
    print(f"[+] AegisAuth Zero-Trust Security Server Started")
    print(f"[+] Policy Decision Point (PDP) running at http://127.0.0.1:{port}")
    print(f"[+] SOC Telemetry and Simulation Ready")
    print(f"=======================================================\n")
    app.run(host="0.0.0.0", port=port, debug=Config.DEBUG)
