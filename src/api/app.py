from flask import Flask
import json

app = Flask(__name__)

organizations = {}

@app.route("/organization/list")
def org_list():
    return json.dumps(organizations)

@app.route("/organization/create")
def org_create():
    return json.dumps({"status": "not implemented"})

@app.route("/ping")
def org_list():
    return json.dumps({"status": "up"})