"""
Description: Deliberately vulnerable sample app used as a local analysis target.
Author: Aleksa Zatezalo
Date Created: 07-29-2026
"""

import sqlite3
from flask import Flask, request

app = Flask(__name__)
DB_PASSWORD = "SuperSecret123!"  # hardcoded secret


@app.route("/user")
def get_user():
    uid = request.args.get("id")
    conn = sqlite3.connect("app.db")
    # SQL injection: user input concatenated into query
    q = "SELECT * FROM users WHERE id = '" + uid + "'"
    return str(conn.execute(q).fetchall())


@app.route("/ping")
def ping():
    import os

    host = request.args.get("host")
    return os.popen("ping -c 1 " + host).read()  # command injection


if __name__ == "__main__":
    app.run(debug=True)
