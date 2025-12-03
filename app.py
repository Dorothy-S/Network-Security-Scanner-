from flask import Flask, render_template, request, jsonify
import socket
from datetime import datetime

app = Flask(__name__)

# Logs messages
def log(msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("scan_log.txt", "a") as f:
        f.write(f"[{timestamp}] {msg}\n") # Writes message with timestamp

# Checks port
def check_port(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # TCP
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        sock.close()
        return result == 0 # If resulet is 0, port is open
    except:
        return False

# Scans ports
def scan_ports(target):
    ports = [22,53,80,110] # Common ports
    open_ports = [p for p in ports if check_port(target, p)] # Checks each port
    log(f"Port scan on {target}: {open_ports}") # Logs results
    return open_ports

# Website security check
def website_security(website):
    issues = []
  # Checks if port 80 is open
    if check_port(website, 80):
        issues.append("HTTP (port 80) open - not secure")
    log(f"Website check on {website}: {issues or 'No issues'}")
    return issues

# Password check
def password_check(pw):
    score = sum([ # Keeps count of each thing in password
        len(pw)>=8,
        any(c.isdigit() for c in pw),
        any(c.isupper() for c in pw),
        any(c.islower() for c in pw),
        any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in pw)
    ])
    log(f"Password checked: {pw}, score: {score}/5")
    return score






# Routes
@app.route("/")
def index():
    return render_template("index.html") # Route to HTML page

# Scanning port route
@app.route("/ports", methods=["POST"])
def ports():
    target = request.form.get("target") # Gets the target from  form
    return jsonify({"open_ports": scan_ports(target)}) # Returns open ports as JSON

# Website security route
@app.route("/website", methods=["POST"])
def website():
    site = request.form.get("website")
    return jsonify({"issues": website_security(site)})

# Password strength route
@app.route("/password", methods=["POST"])
def password():
    pw = request.form.get("password")
    return jsonify({"score": password_check(pw)})

# Logs
@app.route("/log")
def view_log():
    try:
        with open("scan_log.txt") as f:
            return jsonify({"log": f.read()})
    except:
        return jsonify({"log": "No logs yet."})




if __name__ == "__main__":
    app.run(debug=True)
