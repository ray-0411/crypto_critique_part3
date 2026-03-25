from flask import Flask, render_template, request, jsonify, session
import json
import os
import base64
import secrets

from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
)
from webauthn.helpers import (
    parse_registration_credential_json,
    parse_authentication_credential_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    PublicKeyCredentialDescriptor,
)

app = Flask(__name__)
app.secret_key = "dev-secret-key-change-this-later"

USER_FILE = "users.json"

RP_ID = "localhost"
RP_NAME = "WebAuthn Demo"
EXPECTED_ORIGIN = "http://localhost:5000"


def load_users():
    if not os.path.exists(USER_FILE):
        return {}
    with open(USER_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_users(users):
    with open(USER_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2, ensure_ascii=False)


def bytes_to_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("utf-8")


def base64url_to_bytes(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def registration_options_to_json(options):
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


def authentication_options_to_json(options):
    return {
        "challenge": bytes_to_base64url(options.challenge),
        "timeout": options.timeout,
        "rpId": options.rp_id,
        "allowCredentials": [
            {
                "type": c.type,
                "id": bytes_to_base64url(c.id),
            }
            for c in (options.allow_credentials or [])
        ],
        "userVerification": options.user_verification,
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register_begin", methods=["POST"])
def register_begin():
    data = request.json or {}
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

    session["register_username"] = username
    session["register_challenge"] = bytes_to_base64url(options.challenge)

    return jsonify({
        "status": "ok",
        "options": registration_options_to_json(options)
    })


@app.route("/register_complete", methods=["POST"])
def register_complete():
    data = request.json or {}
    username = data.get("username")
    credential_json = data.get("credential")

    if not username or not credential_json:
        return jsonify({
            "status": "error",
            "message": "Missing username or credential"
        })

    expected_username = session.get("register_username")
    expected_challenge_b64 = session.get("register_challenge")

    if not expected_username or not expected_challenge_b64:
        return jsonify({
            "status": "error",
            "message": "Registration session expired"
        })

    if username != expected_username:
        return jsonify({
            "status": "error",
            "message": "Username mismatch"
        })

    users = load_users()
    if username in users:
        return jsonify({
            "status": "error",
            "message": "Username already registered"
        })

    try:
        credential = parse_registration_credential_json(json.dumps(credential_json))

        verification = verify_registration_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(expected_challenge_b64),
            expected_rp_id=RP_ID,
            expected_origin=EXPECTED_ORIGIN,
            require_user_verification=False,
        )

        users[username] = {
            "credential_id": bytes_to_base64url(verification.credential_id),
            "public_key": bytes_to_base64url(verification.credential_public_key),
            "sign_count": verification.sign_count,
        }
        save_users(users)

        session.pop("register_username", None)
        session.pop("register_challenge", None)

        return jsonify({
            "status": "ok",
            "message": f"User {username} registered successfully!"
        })

    except Exception as e:
        print("Registration error:", e)
        return jsonify({
            "status": "error",
            "message": "Registration failed"
        }), 400


@app.route("/login_begin", methods=["POST"])
def login_begin():
    data = request.json or {}
    username = data.get("username", "").strip()

    if not username:
        return jsonify({
            "status": "error",
            "message": "Username cannot be empty"
        })

    users = load_users()
    if username not in users:
        return jsonify({
            "status": "error",
            "message": "Username not registered"
        })

    user = users[username]

    options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=[
            PublicKeyCredentialDescriptor(
                id=base64url_to_bytes(user["credential_id"])
            )
        ],
        user_verification=UserVerificationRequirement.PREFERRED,
    )

    session["login_username"] = username
    session["login_challenge"] = bytes_to_base64url(options.challenge)

    return jsonify({
        "status": "ok",
        "options": authentication_options_to_json(options)
    })


@app.route("/login_complete", methods=["POST"])
def login_complete():
    data = request.json or {}
    username = data.get("username")
    credential_json = data.get("credential")

    if not username or not credential_json:
        return jsonify({
            "status": "error",
            "message": "Missing username or credential"
        })

    expected_username = session.get("login_username")
    expected_challenge_b64 = session.get("login_challenge")

    if not expected_username or not expected_challenge_b64:
        return jsonify({
            "status": "error",
            "message": "Login session expired"
        })

    if username != expected_username:
        return jsonify({
            "status": "error",
            "message": "Username mismatch"
        })

    users = load_users()
    if username not in users:
        return jsonify({
            "status": "error",
            "message": "Username not registered"
        })

    user = users[username]

    try:
        credential = parse_authentication_credential_json(json.dumps(credential_json))

        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(expected_challenge_b64),
            expected_rp_id=RP_ID,
            expected_origin=EXPECTED_ORIGIN,
            credential_public_key=base64url_to_bytes(user["public_key"]),
            credential_current_sign_count=user["sign_count"],
            require_user_verification=False,
        )

        print("stored sign_count =", user["sign_count"])
        print("new sign_count =", verification.new_sign_count)
        print("credential id =", user["credential_id"])

        user["sign_count"] = verification.new_sign_count
        save_users(users)

        session.pop("login_username", None)
        session.pop("login_challenge", None)

        return jsonify({
            "status": "ok",
            "message": f"User {username} login successful!"
        })

    except Exception as e:
        print("Login error:", e)
        return jsonify({
            "status": "error",
            "message": "Login failed"
        }), 400


if __name__ == "__main__":
    app.run(debug=True, host="localhost", port=5000)