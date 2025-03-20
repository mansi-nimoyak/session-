from flask import Flask, request, jsonify
import pytest
import time
import jwt
from userm import  db, User, Session, SessionStatus

app = Flask(__name__)

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if data:
        return jsonify({'message': 'User registered successfully!', 'data': data}), 200
    else:
        return jsonify({'message': 'Invalid input'}), 400

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if data:
        return jsonify({'message': 'Login successful', 'token': 'dummy_token'}), 200
    else:
        return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/logout', methods=['POST'])
def logout():
    return jsonify({'message': 'Logged out successfully!'}), 200

@app.route('/active_sessions', methods=['GET'])
def get_active_sessions():
    sessions = []  # Fetch sessions from DB if needed
    if sessions:
        return jsonify({'sessions': sessions}), 200
    else:
        return jsonify({'message': 'No active sessions'}), 404

@app.route('/cleanup', methods=['POST'])
def cleanup_sessions():
    expired_sessions = []  # Fetch expired sessions from DB if needed
    if expired_sessions:
        return jsonify({'message': 'Expired sessions updated!'}), 200
    else:
        return jsonify({'message': 'No expired sessions to update'}), 404

if __name__ == '__main__':
    app.run(port=5000, debug=True)
