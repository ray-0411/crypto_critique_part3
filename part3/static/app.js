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

        console.log("Registration credential:", credential);
        messageEl.textContent = "Passkey created successfully (not saved to server yet)";
    } catch (err) {
        console.error(err);
        messageEl.textContent = `Registration failed or cancelled: ${err.message}`;
    }
});

// Login
document.getElementById("loginBtn").addEventListener("click", async () => {
    const username = document.getElementById("username").value;
    document.getElementById("message").textContent = `Login clicked: ${username}`;
});