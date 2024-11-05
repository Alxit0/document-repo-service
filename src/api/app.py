import base64
from functools import wraps
from flask import Flask, jsonify, request
import json

from database import initialize_db, close_db, get_db
from costum_auth import verify_client_identity, verify_token, write_token

app = Flask(__name__)

# database setup
app.teardown_appcontext(close_db)
with app.app_context():
    initialize_db()

# utils
def verify_session():
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # get payload from request
            data = request.get_json()
            if not data:
                return jsonify({"error": "No JSON payload found"}), 400
            
            # extract session token
            token = data['session']
            if not token:
                return jsonify({"error": "Session token is missing"}), 401
            
            # validate the token
            if not verify_token(token):
                return jsonify({"error": "Invalid session token"}), 403
            
            return func(*args, **kwargs)
        
        return wrapper
    
    return decorator


# endpoints
@app.route("/organization/list")
def org_list():
    db = get_db()
    cur = db.cursor()

    try:
        cur.execute(
            """
            SELECT
                organizations.name AS organization_name,
                subjects.username AS creator_username
            FROM
                organizations
            JOIN
                subjects ON organizations.created_by = subjects.id;"""
        )
        
        organizations = cur.fetchall()

        org_list = [
            {"organization_name": org[0], "creator_username": org[1]}
            for org in organizations
        ]

        return jsonify({"status": "success", "organizations": org_list})
    
    except Exception as e:
        db.rollback()
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500
    
    finally:
        cur.close()


@app.route("/organization/create", methods=['POST'])
def org_create():
    db = get_db()
    cur = db.cursor()

    data = request.get_json()

    # Validate required fields
    required_fields = ['organization', 'username', 'name', 'email', 'public_key']
    needed_fields = []
    for field in required_fields:
        if field not in data:
            needed_fields.append(field)
    
    if needed_fields:
        return jsonify({"error": "Bad Request", "message": [f"{field} is required" for field in needed_fields]}), 400

    # data parsing
    organization = data['organization']
    username = data['username']
    name = data['name']
    email = data['email']
    public_key = data['public_key']

    try:
        # get user id
        cur.execute("SELECT id FROM subjects WHERE username=?", (username,))
        user_id = cur.fetchone()

        # check if user exists
        if user_id is None:
            cur.execute("INSERT INTO subjects (username, full_name, email, public_key) VALUES (?, ?, ?, ?);", (username, name, email, public_key))
            user_id = cur.lastrowid
        else:
            user_id = user_id[0]

        # create the organization
        cur.execute("INSERT INTO organizations (name, created_by) VALUES (?, ?);", (organization, user_id))
        db.commit()

        return jsonify({"id": cur.lastrowid, "organization": organization, "created_by": user_id}), 201

    except Exception as e:
        db.rollback()
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500

    finally:
        cur.close()


@app.route("/session/create", methods=['POST'])
def authenticate():
    """
    Endpoint to verify client's identity.
    Expected JSON payload:
    {
        "organization": "organization_name"
        "username": "client_username",
        "password": "client_password",
        "encrypted_private_key": "base64_encoded_encrypted_private_key"
    }
    """
    data = request.json
    cur = get_db().cursor()
    
    # Validate required fields
    required_fields = ['organization', 'username', 'password', 'encrypted_private_key']
    needed_fields = []
    for field in required_fields:
        if field not in data:
            needed_fields.append(field)
    
    if needed_fields:
        return jsonify({"error": "Bad Request", "message": [f"{field} is required" for field in needed_fields]}), 400
    
    # data parsing
    username = data["username"]
    password = data["password"]
    encrypted_private_key_b64 = data["encrypted_private_key"]
    organization_name = data["organization"]
    
    # Decode the base64-encoded encrypted private key
    try:
        encrypted_private_key_bytes = base64.b64decode(encrypted_private_key_b64)
    except base64.binascii.Error:
        return jsonify({"error": "Invalid base64 encoding for private key"}), 400
    
    # Retrieve the stored public key for the username
    cur.execute("SELECT public_key FROM subjects WHERE username == ?", (username,))
    stored_public_key_bytes:str = cur.fetchone()
    
    if stored_public_key_bytes is None:
        return jsonify({"error": "User not found"}), 404

    stored_public_key_bytes = stored_public_key_bytes[0]


    # Verify the identity
    is_verified = verify_client_identity(password, encrypted_private_key_bytes, stored_public_key_bytes.encode())

    # Get organization
    cur.execute("SELECT id FROM organizations WHERE name == ?", (organization_name,))
    org_id = cur.fetchmany()
    if not org_id:
        return jsonify({"error": "Organization not found"}), 404

    # Return result
    if is_verified:
        return jsonify({"message": "Authentication successful", "session_token": write_token({"id": 1})}), 200
    
    return jsonify({"message": "Authentication failed. Incorrect password or private key."}), 401

@app.route("/ping")
def ping():
    return json.dumps({"status": "up"})


if __name__ == '__main__':
    app.run(debug=True)