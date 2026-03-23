from flask import Flask, render_template, request, jsonify
import json
import os
import secrets

from webauthn import generate_registration_options
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
)

app = Flask(__name__)
app.secret_key = "dev-secret-key"

USER_FILE = "users.json"

RP_ID = "localhost"
RP_NAME = "WebAuthn Demo"

def load_users():
    if not os.path.exists(USER_FILE):
        return {}
    with open(USER_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_users(users):
    with open(USER_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2, ensure_ascii=False)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register_begin", methods=["POST"])
def register_begin():
    data = request.json
    username = data.get("username", "").strip()

    if not username:
        return jsonify({
            "status": "error",
            "message": "Username cannot be empty"
        })

    users = load_users()

    if username in users:
        return jsonify({
            "status": "error",
            "message": "Username already registered"
        })

    user_id = secrets.token_bytes(16)

    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=user_id,
        user_name=username,
        user_display_name=username,
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
        exclude_credentials=[],
    )

    # 先暫時只把 challenge 和 user_id 存在記憶體回傳前端即可
    # 下一步完成註冊時，才會真的寫入 users.json

    return jsonify({
        "status": "ok",
        "options": options_to_json(options)
    })

def options_to_json(options):
    return {
        "rp": {
            "name": options.rp.name,
            "id": options.rp.id,
        },
        "user": {
            "id": bytes_to_base64url(options.user.id),
            "name": options.user.name,
            "displayName": options.user.display_name,
        },
        "challenge": bytes_to_base64url(options.challenge),
        "pubKeyCredParams": [
            {
                "type": p.type,
                "alg": p.alg,
            }
            for p in options.pub_key_cred_params
        ],
        "timeout": options.timeout,
        "excludeCredentials": [
            {
                "id": bytes_to_base64url(c.id),
                "type": c.type,
            }
            for c in (options.exclude_credentials or [])
        ],
        "authenticatorSelection": None if options.authenticator_selection is None else {
            "residentKey": options.authenticator_selection.resident_key,
            "userVerification": options.authenticator_selection.user_verification,
            "requireResidentKey": options.authenticator_selection.require_resident_key,
        },
        "attestation": options.attestation,
    }

import base64

def bytes_to_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("utf-8")

if __name__ == "__main__":
    app.run(debug=True)