from flask import Flask, request, jsonify, make_response 
from flask_sqlalchemy import SQLAlchemy
import yaml
import bcrypt
import jwt
import pytz
from datetime import datetime, timedelta
from enum import Enum
from functools import wraps

# Load YAML configuration
with open("config.yaml", "r") as file:
    config = yaml.safe_load(file)

IST = pytz.timezone("Asia/Kolkata")

# Initialize Flask app
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = f"mysql+mysqlconnector://{config['db']['user']}:{config['db']['password']}@{config['db']['host']}/{config['db']['database']}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = config["jwt_secret"]

# Initialize database
db = SQLAlchemy(app)

class SessionStatus(Enum):
    ACTIVE = "active"
    EXPIRED = "expired"

# User model
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

# Session model
class Session(db.Model):
    __tablename__ = "sessions"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    session_id = db.Column(db.String(255), unique=True, nullable=False)
    login_time = db.Column(db.DateTime, default=lambda: datetime.now(IST), nullable=False)
    expiry = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.Enum(SessionStatus), default=SessionStatus.ACTIVE, nullable=False)

    def update_status(self):
        """Update the session status based on expiry time."""
        if datetime.utcnow() > self.expiry:
            self.status = SessionStatus.EXPIRED
            db.session.commit()

# Create tables if not exist
with app.app_context():
    db.create_all()

# JWT Authentication Decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if not auth_header or "Bearer " not in auth_header:
            return jsonify({"message": "Token is missing!"}), 401

        token = auth_header.split()[1]

        try:
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"], options={"verify_exp": False})
            user_session = Session.query.filter_by(session_id=data["session_id"]).first()

            if not user_session:
                return jsonify({"message": "Session expired or invalid!"}), 401

            user_session.update_status()
            if user_session.status == SessionStatus.EXPIRED:
                return jsonify({"message": "Token has expired!"}), 401

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

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
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

    session_id = f"{username}_{datetime.now(IST).timestamp()}"
    login_time = datetime.now(IST)
    expiry_time = login_time + timedelta(minutes=5)

    new_session = Session(user_id=user.id, session_id=session_id, login_time=login_time, expiry=expiry_time, status=SessionStatus.ACTIVE)
    db.session.add(new_session)
    db.session.commit()

    token = jwt.encode({"user_id": user.id, "session_id": session_id, "exp": expiry_time.timestamp()}, app.config["SECRET_KEY"], algorithm="HS256")

    return jsonify({
        "token": token,
        "login_time": login_time.strftime("%Y-%m-%d %H:%M:%S IST"),
        "expires_at": expiry_time.strftime("%Y-%m-%d %H:%M:%S IST")
    })

@app.route("/cleanup", methods=["POST"])
def cleanup_sessions():
    expired_sessions = Session.query.filter(Session.expiry < datetime.utcnow()).all()
    for session in expired_sessions:
        session.status = SessionStatus.EXPIRED
    db.session.commit()
    return jsonify({"message": "Expired sessions updated!"})

# Run Flask app
if __name__ == "__main__":
    app.run(debug=True)
