from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from datetime import datetime
import requests

app = Flask(__name__)
app.secret_key = "supersecretkey"
DATABASE = "project.db"


def get_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    # Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)

    # Applications table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS applications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            app_name TEXT NOT NULL,
            business_name TEXT NOT NULL,
            target_url TEXT NOT NULL,
            tech_stack TEXT NOT NULL,
            description TEXT NOT NULL
        )
    """)

    # Scan results table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            application_id INTEGER,
            tool_name TEXT NOT NULL,
            vulnerability TEXT NOT NULL,
            severity TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            status TEXT NOT NULL,
            scan_time TEXT NOT NULL,
            FOREIGN KEY (application_id) REFERENCES applications(id)
        )
    """)

    # Scan history table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            application_id INTEGER,
            scan_name TEXT NOT NULL,
            run_by TEXT NOT NULL,
            total_findings INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (application_id) REFERENCES applications(id)
        )
    """)

    # Insert default users
    cursor.execute("SELECT * FROM users WHERE username = ?", ("admin",))
    if cursor.fetchone() is None:
        cursor.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ("admin", "admin123", "admin")
        )

    conn.commit()
    conn.close()


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, password)
        )
        user = cursor.fetchone()
        conn.close()

        if user:
            session["username"] = user["username"]
            session["role"] = user["role"]
            return redirect(url_for("admin_dashboard"))
        else:
            message = "Invalid username or password"

    return render_template("login.html", message=message)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        confirm = request.form["confirm"]

        if password != confirm:
            return render_template("register.html", message="Passwords do not match")

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            conn.close()
            return render_template("register.html", message="Username already exists")

        cursor.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (username, password, "admin")
        )

        conn.commit()
        conn.close()

        flash("Admin account created successfully. Please login.")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/admin_dashboard")
def admin_dashboard():
    if "username" not in session or session["role"] != "admin":
        return redirect(url_for("login"))

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) AS count FROM applications")
    total_apps = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) AS count FROM scan_results")
    total_results = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) AS count FROM scan_results WHERE severity = 'High'")
    high_count = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) AS count FROM scan_results WHERE severity = 'Medium'")
    medium_count = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) AS count FROM scan_results WHERE severity = 'Low'")
    low_count = cursor.fetchone()["count"]

    risk_score = (high_count * 5) + (medium_count * 3) + (low_count * 1)

    if risk_score >= 15:
        risk_level = "High Risk"
    elif risk_score >= 7:
        risk_level = "Moderate Risk"
    elif risk_score > 0:
        risk_level = "Low Risk"
    else:
        risk_level = "No Active Risk"

    cursor.execute("""
        SELECT scan_history.*, applications.app_name
        FROM scan_history
        LEFT JOIN applications ON scan_history.application_id = applications.id
        ORDER BY scan_history.id DESC
        LIMIT 5
    """)
    recent_scans = cursor.fetchall()

    conn.close()

    return render_template (
        "admin_dashboard.html",
        username=session["username"],
        total_apps=total_apps,
        total_results=total_results,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        recent_scans=recent_scans,
        risk_score = risk_score,
        risk_level = risk_level
    )


@app.route("/add_application", methods=["GET", "POST"])
def add_application():
    if "username" not in session or session["role"] != "admin":
        return redirect(url_for("login"))

    if request.method == "POST":
        app_name = request.form["app_name"]
        business_name = request.form["business_name"]
        target_url = request.form["target_url"]
        tech_stack = request.form["tech_stack"]
        description = request.form["description"]

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO applications (app_name, business_name, target_url, tech_stack, description)
            VALUES (?, ?, ?, ?, ?)
        """, (app_name, business_name, target_url, tech_stack, description))
        conn.commit()
        conn.close()

        flash("SME application registered successfully.")
        return redirect(url_for("applications"))

    return render_template("add_application.html")


@app.route("/applications")
def applications():
    if "username" not in session or session["role"] != "admin":
        return redirect(url_for("login"))

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM applications ORDER BY id DESC")
    apps = cursor.fetchall()
    conn.close()

    return render_template("applications.html", apps=apps)


@app.route("/scan_results")
def scan_results():
    if "username" not in session or session["role"] != "admin":
        return redirect(url_for("login"))

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT scan_results.*, applications.app_name
        FROM scan_results
        LEFT JOIN applications ON scan_results.application_id = applications.id
        ORDER BY scan_results.id DESC
    """)
    results = cursor.fetchall()
    conn.close()

    return render_template("scan_results.html", results=results)


@app.route("/recommendations")
def recommendations():
    if "username" not in session or session["role"] != "admin":
        return redirect(url_for("login"))

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT scan_results.*, applications.app_name
        FROM scan_results
        LEFT JOIN applications ON scan_results.application_id = applications.id
        ORDER BY scan_results.id DESC
    """)
    recommendations = cursor.fetchall()
    conn.close()

    return render_template("recommendations.html", recommendations=recommendations)


@app.route("/scan_history")
def scan_history():
    if "username" not in session or session["role"] != "admin":
        return redirect(url_for("login"))

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT scan_history.*, applications.app_name
        FROM scan_history
        LEFT JOIN applications ON scan_history.application_id = applications.id
        ORDER BY scan_history.id DESC
    """)
    history = cursor.fetchall()
    conn.close()

    return render_template("scan_history.html", history=history)


@app.route("/run_scan/<int:app_id>")
def run_scan(app_id):
    if "username" not in session or session["role"] != "admin":
        return redirect(url_for("login"))

    conn = get_connection()
    cursor = conn.cursor()

    # Get selected SME application
    cursor.execute("SELECT * FROM applications WHERE id = ?", (app_id,))
    target_app = cursor.fetchone()

    if not target_app:
        conn.close()
        flash("Application not found.")
        return redirect(url_for("applications"))

    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    findings = []

    target_url = target_app["target_url"]

    try:
        response = requests.get(target_url, timeout=5)

        if response.status_code == 200:
            findings.append((
                app_id,
                "System Check",
                "Target application is reachable",
                "Low",
                "Application endpoint responded successfully. Continue periodic monitoring to ensure availability.",
                "Info",
                current_time
            ))
        else:
            findings.append((
                app_id,
                "System Check",
                f"Unexpected HTTP status code: {response.status_code}",
                "Medium",
                "Verify application availability and review server-side response behavior.",
                "Open",
                current_time
            ))

        security_headers = [
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Strict-Transport-Security"
        ]

        for header in security_headers:
            if header not in response.headers:
                findings.append((
                    app_id,
                    "OWASP ZAP",
                    f"Missing security header: {header}",
                    "High" if header in ["Content-Security-Policy", "Strict-Transport-Security"] else "Medium",
                    f"Configure the {header} header to reduce browser-based attack exposure and improve application hardening.",
                    "Open",
                    current_time
                ))

        if "Server" in response.headers:
            findings.append((
                app_id,
                "System Check",
                "Server information disclosure detected",
                "Low",
                "Minimize server header exposure to reduce unnecessary information leakage.",
                "Open",
                current_time
            ))

        tech_stack = target_app["tech_stack"].lower()

        if "flask" in tech_stack or "python" in tech_stack:
            findings.append((
                app_id,
                "Bandit",
                "Potential insecure coding pattern in Python application",
                "Medium",
                "Review source code using static analysis and replace unsafe coding constructs with secure alternatives.",
                "Open",
                current_time
            ))

        findings.append((
            app_id,
            "OWASP ZAP",
            "Potential input validation weakness (simulated XSS risk)",
            "Medium",
            "Validate, sanitize, and encode user inputs before storing or rendering them.",
            "Open",
            current_time
        ))

    except requests.exceptions.RequestException:
        findings.append((
            app_id,
            "System Check",
            "Target application is unreachable",
            "High",
            "Verify that the SME application is online and accessible before running security assessment.",
            "Open",
            current_time
        ))

    # Store results
    cursor.executemany("""
        INSERT INTO scan_results (
            application_id, tool_name, vulnerability, severity,
            recommendation, status, scan_time
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
    """, findings)

    cursor.execute("""
        INSERT INTO scan_history (application_id, scan_name, run_by, total_findings, timestamp)
        VALUES (?, ?, ?, ?, ?)
    """, (
        app_id,
        f"Security Scan - {target_app['app_name']}",
        session["username"],
        len(findings),
        current_time
    ))

    conn.commit()
    conn.close()

    flash(f"Security scan completed for {target_app['app_name']}.")
    return redirect(url_for("scan_results"))

    # Demo results linked to selected application
    demo_results = [
        (app_id, "Bandit", "Hardcoded password found", "Medium",
         "Remove hardcoded credentials and use environment variables.", "Open", current_time),

        (app_id, "OWASP ZAP", "Missing security headers", "High",
         "Enable headers such as Content-Security-Policy and X-Frame-Options.", "Open", current_time),

        (app_id, "OWASP ZAP", "Potential XSS input point", "Medium",
         "Sanitize and validate all user input before rendering.", "Open", current_time),

        (app_id, "Bandit", "Use of unsafe function", "Low",
         "Replace unsafe functions with secure alternatives.", "Open", current_time)
    ]

    cursor.executemany("""
        INSERT INTO scan_results (
            application_id, tool_name, vulnerability, severity,
            recommendation, status, scan_time
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
    """, demo_results)

    cursor.execute("""
        INSERT INTO scan_history (application_id, scan_name, run_by, total_findings, timestamp)
        VALUES (?, ?, ?, ?, ?)
    """, (app_id, f"Security Scan - {target_app['app_name']}", session["username"], len(demo_results), current_time))

    conn.commit()
    conn.close()

    flash(f"Security scan completed for {target_app['app_name']}.")
    return redirect(url_for("scan_results"))


@app.route("/clear_results")
def clear_results():
    if "username" not in session or session["role"] != "admin":
        return redirect(url_for("login"))

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scan_results")
    cursor.execute("DELETE FROM scan_history")
    conn.commit()
    conn.close()

    flash("All scan results and history cleared.")
    return redirect(url_for("admin_dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True)