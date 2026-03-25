function base64urlToUint8Array(base64url) {
    const padding = '='.repeat((4 - base64url.length % 4) % 4);
    const base64 = (base64url + padding).replace(/-/g, '+').replace(/_/g, '/');
    const raw = atob(base64);
    const result = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) {
        result[i] = raw.charCodeAt(i);
    }
    return result;
}

function bufferToBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let str = "";
    for (let i = 0; i < bytes.length; i++) {
        str += String.fromCharCode(bytes[i]);
    }
    return btoa(str)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
}

// Register
document.getElementById("registerBtn").addEventListener("click", async () => {
    const username = document.getElementById("username").value.trim();
    const messageEl = document.getElementById("message");

    if (!username) {
        messageEl.textContent = "Please enter a username";
        return;
    }

    try {
        const res = await fetch("/register_begin", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ username })
        });

        const data = await res.json();

        if (data.status !== "ok") {
            messageEl.textContent = data.message;
            return;
        }

        const options = data.options;

        options.challenge = base64urlToUint8Array(options.challenge);
        options.user.id = base64urlToUint8Array(options.user.id);

        if (options.excludeCredentials) {
            options.excludeCredentials = options.excludeCredentials.map(cred => ({
                ...cred,
                id: base64urlToUint8Array(cred.id)
            }));
        }

        const credential = await navigator.credentials.create({
            publicKey: options
        });

        // 🔥 把 credential 轉成 JSON 可傳格式
        const credentialData = {
            id: credential.id,
            rawId: bufferToBase64url(credential.rawId),
            type: credential.type,
            response: {
                clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
                attestationObject: bufferToBase64url(credential.response.attestationObject)
            }
        };

        // 🔥 傳回後端
        const finishRes = await fetch("/register_complete", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                username,
                credential: credentialData
            })
        });

        const finishData = await finishRes.json();

        messageEl.textContent = finishData.message;

        console.log("Registration credential:", credential);
        messageEl.textContent = "Passkey created successfully";
    } catch (err) {
        console.error(err);

        if (err.name === "NotAllowedError") {
            messageEl.textContent = "Registration canceled";
        } else {
            messageEl.textContent = "Registration failed";
        }
    }
});

// Login
document.getElementById("loginBtn").addEventListener("click", async () => {
    const username = document.getElementById("username").value.trim();
    const messageEl = document.getElementById("message");

    if (!username) {
        messageEl.textContent = "Please enter a username";
        return;
    }

    try {
        const res = await fetch("/login_begin", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ username })
        });

        const data = await res.json();

        if (data.status !== "ok") {
            messageEl.textContent = data.message;
            return;
        }

        const options = data.options;

        options.challenge = base64urlToUint8Array(options.challenge);

        if (options.allowCredentials) {
            options.allowCredentials = options.allowCredentials.map(cred => ({
                ...cred,
                id: base64urlToUint8Array(cred.id)
            }));
        }

        const assertion = await navigator.credentials.get({
            publicKey: options
        });

        const credentialData = {
            id: assertion.id,
            rawId: bufferToBase64url(assertion.rawId),
            type: assertion.type,
            response: {
                clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON),
                authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
                signature: bufferToBase64url(assertion.response.signature),
                userHandle: assertion.response.userHandle
                    ? bufferToBase64url(assertion.response.userHandle)
                    : null
            }
        };

        const finishRes = await fetch("/login_complete", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                username,
                credential: credentialData
            })
        });

        const finishData = await finishRes.json();
        messageEl.textContent = finishData.message;

    } catch (err) {
        console.error(err);

        if (err.name === "NotAllowedError") {
            messageEl.textContent = "Login canceled";
        } else {
            messageEl.textContent = "Login failed";
        }
    }
});