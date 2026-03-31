# Safe Python file — no vulnerabilities

import hashlib
import os
import yaml
from flask import Flask, redirect

# Safe: parameterized query
def get_user(db, user_id):
    return db.execute("SELECT * FROM users WHERE id = ?", (user_id,))

# Safe: strong hash
def hash_data(data):
    return hashlib.sha256(data.encode()).hexdigest()

# Safe: safe yaml loading
def load_config(path):
    with open("config.yml") as f:
        return yaml.safe_load(f)

# Safe: environment variable for secrets
db_password = os.environ.get("DB_PASSWORD", "")
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "")
SESSION_COOKIE_SECURE = True

# Safe: no debug in production
DEBUG = False

# Safe: specific CORS origins
CORS_ALLOWED_ORIGINS = ["https://example.com"]

# Safe: static redirect
def handle_login():
    return redirect("/dashboard")

# Safe: static command
def list_files():
    os.system("ls -la /tmp")
