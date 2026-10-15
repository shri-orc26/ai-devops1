import os
import sqlite3
from flask import Flask, request, jsonify
from utils.auth import verify_token
from database.db_handler import execute_query
from werkzeug.security import check_password_hash
import jwt, datetime
from functools import wraps

app = Flask(__name__)

# FIX: Load secret from environment variable
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY environment variable not set")

# FIX: Debug disabled — set via env only
app.config['DEBUG'] = os.environ.get("FLASK_DEBUG", "false").lower() == "true"

# FIX: Rate limiting
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
limiter = Limiter(get_remote_address, app=app, default_limits=["100/hour"])

@app.route('/login', methods=['POST'])
@limiter.limit("10/minute")
def login():
    data     = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # FIX: Parameterized query + bcrypt password check
    conn   = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    if user and check_password_hash(user[1], password):
        token = jwt.encode(
            {"user_id": user[0], "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
            SECRET_KEY, algorithm="HS256"
        )
        return jsonify({"status": "success", "token": token})
    return jsonify({"status": "failed"}), 401

@app.route('/user/<username>')
def get_user(username):
    # FIX: Parameterized query — no string interpolation
    conn   = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, username FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    return jsonify(user)

@app.route('/data')
def get_data():
    # FIXED: Removed pickle entirely — use JSON
    import json
    data = request.args.get('payload')
    return jsonify(json.loads(data))

@app.route('/admin/delete')
def delete_user():
    try:
        user_id = request.args.get('id')
        # FIX: Parameterized query
        execute_query("DELETE FROM users WHERE id = ?", (user_id,))
        return jsonify({"status": "deleted"})
    except ValueError as e:
        return jsonify({"error": "Invalid user ID"}), 400
    except Exception as e:
        app.logger.error(f"Delete failed: {e}")
        return jsonify({"error": "Internal error"}), 500

@app.route('/')
def home():
    return "Flask app is running!"
if __name__ == '__main__':
    # FIX: Bind to localhost only in dev
    app.run(host='127.0.0.1', port=5000)