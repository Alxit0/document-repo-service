import base64
from functools import wraps
import os
from flask import Flask, jsonify, request
import json

from database import initialize_db, close_db, get_db
from costum_auth import verify_token, write_token, extrat_token_info, verify_signature

app = Flask(__name__)

challenges = {}

# database setup
app.teardown_appcontext(close_db)
with app.app_context():
    initialize_db()

# utils
def verify_args(required_fields):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # get data
            data = request.args if request.method == 'GET' else request.get_json()
            
            # Validate required fields
            needed_fields = []
            for field in required_fields:
                if field not in data:
                    needed_fields.append(field)
            
            if needed_fields:
                return jsonify({"error": "Bad Request", "message": [f"{field} is required" for field in needed_fields]}), 400
            
            return func(*args, **kwargs)
        
        return wrapper
    
    return decorator

def verify_session():
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # get payload from request
            data = request.headers
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
@verify_args(['organization', 'username', 'name', 'email', 'public_key'])
def org_create():
    db = get_db()
    cur = db.cursor()

    # data parsing
    data = request.get_json()
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


@app.route("/session/challenge")
@verify_args(['username'])
def challenge():

    data = request.args

    # check if is already generated
    if data['username'] in challenges:
        return json.dumps({"nounce": base64.b64encode(challenges[data['username']]).decode('utf-8')})

    # gen nonce
    nonce = data['username'].encode() + os.urandom(16)
    challenges[data['username']] = nonce
    
    return json.dumps({"nounce": base64.b64encode(nonce).decode('utf-8')})

@app.route("/session/create", methods=['POST'])
@verify_args(['organization', 'username', 'signature'])
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
    
    # data parsing
    username: str = data["username"]
    organization_name: str = data["organization"]
    signature: str = data["signature"]
    
    # Retrieve the stored public key for the username
    cur.execute("SELECT public_key, id FROM subjects WHERE username == ?", (username,))
    res:str = cur.fetchone()
    
    if res is None:
        return jsonify({"error": "User not found"}), 404

    stored_public_key_bytes = res[0]
    user_id = res[1]


    # Verify the identity
    is_verified = verify_signature(
        stored_public_key_bytes.encode(),
        challenges[username],
        base64.b64decode(signature.encode())
    )
    
    if not is_verified:
        return jsonify({"message": "Authentication failed. Incorrect password or private key."}), 401

    # Get organization
    cur.execute("SELECT id FROM organizations WHERE name == ?", (organization_name,))
    org_id = cur.fetchone()
    if not org_id:
        return jsonify({"error": "Organization not found"}), 404
    org_id = org_id[0]

    # Return result
    token_info = {
        'org': org_id,
        'usr': user_id
    }
    print(token_info)
    return jsonify({"message": "Authentication successful", "session_token": write_token(token_info)}), 200


@app.route("/file/upload", methods=['POST'])
@verify_session()
@verify_args(["encrypted_file", "name", "file_handle", "algorithm", "encryption_key", "iv", "nonce"])
def upload_file():

    data = request.get_json()

    # parse JSON
    encrypted_file = data["encrypted_file"]
    document_name = data["name"]
    file_handle = data["file_handle"]
    
    alg = data["algorithm"]
    encrypted_key = data["encryption_key"]
    iv = data["iv"]
    nonce = data["nonce"]
    
    # Session data
    ses_data = extrat_token_info(request.headers['session'])
    org_id = ses_data['org']
    usr_id = ses_data['usr']

    # insert document into the db
    con = get_db()
    cur = con.cursor()

    try:
        cur.execute(
            """
            INSERT INTO documents (handle, name, organization_id, created_by)
            VALUES (?, ?, ?, ?)
            """,
            (file_handle, document_name, org_id, usr_id)
        )
        doc_id = cur.lastrowid

        cur.execute(
            """
            INSERT INTO document_metadata (document_id, encryption_key, alg, iv, nonce)
            VALUES (?, ?, ?, ?, ?)
            """,
            (doc_id, encrypted_key, alg, iv, nonce)
        )

        con.commit()
    except Exception as e:
        con.rollback()
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500
    finally:
        cur.close()

    # save file
    with open(f"docs_repo/{file_handle}", "+w") as file:
        file.write(encrypted_file)

    return jsonify({
        "status": "Document uploaded successfully",
        "document_id": doc_id,
        "file_handle": file_handle
    }), 200


@app.route("/ping")
def ping():
    return json.dumps({"status": "up"})

@app.route("/file/metadata", methods=['GET'])
@verify_session
@verify_args(["document_name"])
def get_doc_metadata():

    doc_name = request.args.get("document_name")

    session_data = extrat_token_info(request.headers['session'])
    org_id = session_data['org']
    usr_id = session_data['usr']

    db = get_db()
    cur = db.cursor()
    
    try:
        cur.execute("""
                    SELECT
                        d.id AS document_id,
                        d.handle AS file_handle,
                        d.name AS document_name,
                        dm.encryption_key,
                        dm.alg,
                        dm.iv,
                        dm.nonce
                    FROM
                        documents d
                    JOIN
                        document_metadata dm ON d.id = dm.document_id
                    WHERE
                        d.name = ? AND
                        d.organization_id = ? AND
                        d.created_by = ?
                    """
            ,(doc_name,org_id,usr_id)
        )
        
        result = cur.fetchone()

        if result == None:
            return jsonify({"error":"Document not found"}),404
        
        doc_metadata = {
            "document_id": result[0],
            "file_handle": result[1],
            "document_name": result[2],
            "encryption_key": result[3],
            "algorithm": result[4],
            "iv": result[5],
            "nonce": result[6]
        }

        return jsonify({"status": "success", "metadata": doc_metadata}),200
    except Exception as e:
        db.rollback()
        return jsonify({""}), 500




if __name__ == '__main__':
    app.run(debug=True)