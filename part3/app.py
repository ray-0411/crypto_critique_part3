from flask import Flask, render_template, request, jsonify
import json
import os

app = Flask(__name__)

USER_FILE = "users.json"

# 讀取使用者
def load_users():
    if not os.path.exists(USER_FILE):
        return {}
    with open(USER_FILE, "r") as f:
        return json.load(f)

# 儲存使用者
def save_users(users):
    with open(USER_FILE, "w") as f:
        json.dump(users, f, indent=2)

@app.route("/")
def index():
    return render_template("index.html")

# 註冊（現在會真的存）
@app.route("/register_start", methods=["POST"])
def register_start():
    data = request.json
    username = data.get("username")

    users = load_users()

    # ❌ 已存在
    if username in users:
        return jsonify({
            "status": "error",
            "message": "Username already registered"
        })

    # ✅ 新使用者（先存空資料）
    users[username] = {}
    save_users(users)

    return jsonify({
        "status": "ok",
        "message": f"User {username} registered (temporary)"
    })

# 登入（檢查是否存在）
@app.route("/login_start", methods=["POST"])
def login_start():
    data = request.json
    username = data.get("username")

    users = load_users()

    # ❌ 不存在
    if username not in users:
        return jsonify({
            "status": "error",
            "message": "Username not registered"
        })

    return jsonify({
        "status": "ok",
        "message": f"User {username} exists, ready to login"
    })

if __name__ == "__main__":
    app.run(debug=True)