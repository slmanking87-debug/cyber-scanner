from flask import Flask, render_template, request, redirect, url_for, flash
import csv
import os
from scanner import scan_input, save_history, HISTORY_FILE

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key-before-deployment")


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    scanned_value = ""
    if request.method == "POST":
        scanned_value = request.form.get("value", "").strip()
        result = scan_input(scanned_value)
        if result["kind"] != "invalid":
            save_history(scanned_value, result)
        else:
            flash(result["details"], "warning")
    return render_template("index.html", result=result, scanned_value=scanned_value)


@app.route("/history")
def history():
    rows = []
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, newline="", encoding="utf-8-sig") as file:
            rows = list(csv.DictReader(file))
        rows.reverse()
    return render_template("history.html", rows=rows)


@app.route("/clear-history", methods=["POST"])
def clear_history():
    if os.path.exists(HISTORY_FILE):
        os.remove(HISTORY_FILE)
    flash("تم حذف سجل الفحوصات من هذا الخادم.", "success")
    return redirect(url_for("history"))


if __name__ == "__main__":
    # Local development only. For public deployment use a production WSGI server.
    app.run(host="127.0.0.1", port=5000, debug=True)
