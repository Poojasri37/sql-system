from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List

import pandas as pd
from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from ml_service import get_model_manifest, predict_event

BASE_DIR = Path(__file__).resolve().parent
METRICS_PATH = BASE_DIR / "outputs" / "reports" / "metrics.json"
PREDICTIONS_PATH = BASE_DIR / "outputs" / "reports" / "predictions.csv"

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "sql-anomaly-dev-secret")
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "sql-anomaly-jwt-secret")

jwt = JWTManager(app)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    storage_uri="memory://",
    default_limits=["30 per minute"],
)
bcrypt = Bcrypt(app)

DEFAULT_USERS: Dict[str, str] = {
    "admin": bcrypt.generate_password_hash("admin123").decode("utf-8"),
    "analyst": bcrypt.generate_password_hash("analyst123").decode("utf-8"),
}


def _load_metrics() -> Dict[str, Any]:
    if not METRICS_PATH.exists():
        return {"status": "missing", "message": "metrics file not found"}
    with METRICS_PATH.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _load_alerts(limit: int = 10) -> List[Dict[str, Any]]:
    if not PREDICTIONS_PATH.exists():
        return []
    df = pd.read_csv(PREDICTIONS_PATH)
    if df.empty:
        return []
    df = df[df["predicted_anomaly"] == 1].sort_values("risk_score", ascending=False)
    return df.head(limit).to_dict(orient="records")


@app.route("/")
def index():
    if session.get("username"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        stored_hash = DEFAULT_USERS.get(username)
        if stored_hash and bcrypt.check_password_hash(stored_hash, password):
            session["username"] = username
            return redirect(url_for("dashboard"))
        error = "Invalid username or password."
    return render_template("login.html", error=error, manifest=get_model_manifest())


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    if not session.get("username"):
        return redirect(url_for("login"))
    metrics = _load_metrics()
    alerts = _load_alerts(10)
    return render_template(
        "dashboard.html",
        username=session["username"],
        metrics=metrics,
        alerts=alerts,
        manifest=get_model_manifest(),
    )


@app.route("/api/health")
def api_health():
    return jsonify({
        "status": "ok",
        "model": get_model_manifest()["model_name"],
        "version": get_model_manifest()["model_version"],
        "dataset": get_model_manifest()["training_dataset"],
    })


@app.route("/api/login", methods=["POST"])
def api_login():
    payload = request.get_json(silent=True) or {}
    username = str(payload.get("username") or "").strip()
    password = str(payload.get("password") or "")
    stored_hash = DEFAULT_USERS.get(username)
    if not stored_hash or not bcrypt.check_password_hash(stored_hash, password):
        return jsonify({"error": "Invalid username or password."}), 401
    token = create_access_token(identity=username)
    return jsonify({"access_token": token, "token_type": "Bearer", "user": username})


@app.route("/api/metrics")
def api_metrics():
    return jsonify(_load_metrics())


@app.route("/api/predict", methods=["POST"])
@jwt_required()
@limiter.limit("30/minute")
def api_predict():
    payload = request.get_json(silent=True)
    if payload is None:
        return jsonify({"error": "Request body must be valid JSON."}), 400
    try:
        result = predict_event(payload)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"user": get_jwt_identity(), **result})


@app.route("/api/recent-alerts")
@jwt_required()
def api_recent_alerts():
    return jsonify({"alerts": _load_alerts(10)})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
