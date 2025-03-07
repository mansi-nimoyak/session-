from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import yaml
import bcrypt
import jwt
import threading
import time
from datetime import datetime, timedelta

# Load YAML configuration
with open("config.yaml", "r") as file:
    config = yaml.safe_load(file)

# Initialize Flask app
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = f"mysql+mysqlconnector://{config['db']['user']}:{config['db']['password']}@{config['db']['host']}/{config['db']['database']}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = config["jwt_secret"]

db = SQLAlchemy(app)

# Session Status Enum
class SessionStatus:
    ACTIVE = "active"
    EXPIRED = "expired"

# User Model
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

# Session Model
class Session(db.Model):
    __tablename__ = "sessions"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    session_id = db.Column(db.String(255), unique=True, nullable=False)
    login_time = db.Column(db.BigInteger, nullable=False)  # Epoch timestamp
    expiry = db.Column(db.BigInteger, nullable=False)  # Epoch timestamp
    status = db.Column(db.String(10), default=SessionStatus.ACTIVE, nullable=False)

    def update_status(self):
        if time.time() > self.expiry:
            self.status = SessionStatus.EXPIRED
            db.session.commit()

# Create tables
with app.app_context():
    db.create_all()

# Background thread to check session expiry
def session_monitor():
    while True:
        with app.app_context():
            expired_sessions = Session.query.filter(Session.expiry < time.time(), Session.status == SessionStatus.ACTIVE).all()
            for session in expired_sessions:
                session.status = SessionStatus.EXPIRED
            db.session.commit()
        time.sleep(60)  # Runs every minute

threading.Thread(target=session_monitor, daemon=True).start()

import functools

def token_required(f):
    @functools.wraps(f)  # Preserve original function metadata
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if not auth_header or "Bearer " not in auth_header:
            return jsonify({"message": "Token is missing!"}), 401

        token = auth_header.split()[1]
        try:
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"], options={"verify_exp": False})
            user_session = Session.query.filter_by(session_id=data["session_id"]).first()
            if not user_session or user_session.status == SessionStatus.EXPIRED:
                return jsonify({"message": "Session expired or invalid!"}), 401
            return f(data, *args, **kwargs)
        except jwt.DecodeError:
            return jsonify({"message": "Token is invalid!"}), 401

    return decorated

# Register API
@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username, password = data["username"], data["password"]
    hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    if User.query.filter_by(username=username).first():
        return jsonify({"message": "User already exists!"}), 400

    new_user = User(username=username, password_hash=hashed_pw)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User registered successfully!"})

# Login API
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username, password = data["username"], data["password"]
    user = User.query.filter_by(username=username).first()
    if not user or not bcrypt.checkpw(password.encode("utf-8"), user.password_hash.encode("utf-8")):
        return jsonify({"message": "Invalid credentials!"}), 401

    active_sessions_count = Session.query.filter_by(user_id=user.id, status=SessionStatus.ACTIVE).count()
    if active_sessions_count >= 2:
        return jsonify({"message": "Too many devices logged in!"}), 403

    session_id = f"{username}_{int(time.time())}"
    login_time = int(time.time())
    expiry_time = login_time + 300  # 5 minutes expiry

    new_session = Session(user_id=user.id, session_id=session_id, login_time=login_time, expiry=expiry_time, status=SessionStatus.ACTIVE)
    db.session.add(new_session)
    db.session.commit()

    token = jwt.encode({"user_id": user.id, "session_id": session_id, "exp": expiry_time}, app.config["SECRET_KEY"], algorithm="HS256")
    return jsonify({"token": token, "login_time": login_time, "expires_at": expiry_time})

# Logout API
@app.route("/logout", methods=["POST"])
@token_required
def logout(data):
    session = Session.query.filter_by(session_id=data["session_id"]).first()
    if session:
        session.status = SessionStatus.EXPIRED
        db.session.commit()
        return jsonify({"message": "Logged out successfully!"})
    return jsonify({"message": "Session not found!"}), 400

# Get Active Sessions API
@app.route("/active_sessions", methods=["GET"])
@token_required
def get_active_sessions(data):
    sessions = Session.query.filter_by(user_id=data["user_id"], status=SessionStatus.ACTIVE).all()
    return jsonify([{"session_id": s.session_id, "login_time": s.login_time, "expires_at": s.expiry} for s in sessions])

# Cleanup API
@app.route("/cleanup", methods=["POST"])
def cleanup_sessions():
    expired_sessions = Session.query.filter(Session.expiry < time.time()).all()
    for session in expired_sessions:
        session.status = SessionStatus.EXPIRED
    db.session.commit()
    return jsonify({"message": "Expired sessions updated!"})

# Run Flask app
if __name__ == "__main__":
    app.run(debug=True)
