// Register
document.getElementById("registerBtn").addEventListener("click", async () => {
    const username = document.getElementById("username").value;

    const res = await fetch("/register_start", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ username })
    });

    const data = await res.json();
    document.getElementById("message").textContent = data.message;
});

// Login
document.getElementById("loginBtn").addEventListener("click", async () => {
    const username = document.getElementById("username").value;

    const res = await fetch("/login_start", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ username })
    });

    const data = await res.json();
    document.getElementById("message").textContent = data.message;
});