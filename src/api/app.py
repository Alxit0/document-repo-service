import base64
from cryptography.hazmat.primitives import serialization, hashes
from datetime import datetime
from functools import wraps
import os
from flask import Flask, jsonify, request, send_file, g
import json

from secure_communication import secure_endpoint, parameters, client_shared_keys, get_right_body
from database import initialize_db, close_db, get_db, REPO_PATH, DATABASE
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
            try:
                data = request.decrypted_params
            except:
                request.decrypted_params = get_right_body()
                data = request.decrypted_params

            # Validate required fields
            needed_fields = []
            for field in required_fields:
                
                if type(field) is list:
                    if sum(i in data for i in field) != 1:
                        needed_fields.append(' | '.join(field))

                elif field not in data:
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
            data = request.decrypted_headers
            
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

def verify_permission(required_permission):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            
            return func(*args, **kwargs)
        
        return wrapper
    
    return decorator


# secure comunication setup
@app.route('/get-parameters', methods=['GET'])
def get_parameters():
    data = parameters.parameter_bytes(encoding=serialization.Encoding.PEM, format=serialization.ParameterFormat.PKCS3)
    
    return jsonify({"parameters": base64.b64encode(data).decode()}), 200

@app.route('/dh-init', methods=['POST'])
@verify_args(["client_id", "client_public_key"])
def dh_init():

    data = request.json
    client_id = data["client_id"]
    client_public_key_bytes = base64.b64decode(data["client_public_key"])

    # deserialize client's public key
    client_public_key = serialization.load_pem_public_key(client_public_key_bytes)

    # gen server's private/public key pair
    server_private_key = parameters.generate_private_key()
    server_public_key = server_private_key.public_key()

    # compute shared secret
    shared_secret = server_private_key.exchange(client_public_key)
    
    # Serialize server's public key
    server_public_key_bytes = server_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    digest = hashes.Hash(hashes.SHA256())
    digest.update(shared_secret)
    valid_key = digest.finalize()  # 256-bit (32 bytes) key

    client_shared_keys[client_id] = valid_key

    return jsonify({
        "server_public_key": base64.b64encode(server_public_key_bytes).decode()
    }), 200

@app.route('/jail-house-lock', methods=['GET'])
def clean_database():
    
    db = get_db()
    db.close()

    os.remove(DATABASE)
    g.pop('db')

    with app.app_context():
        initialize_db()

    return jsonify({"status": "success"}), 200


# organization endpoints
@app.route("/organization/list")
@secure_endpoint()
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

        return jsonify({"status": "success", "organizations": org_list}), 200
    
    except Exception as e:
        db.rollback()
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500
    
    finally:
        cur.close()

@app.route("/organization/create", methods=['POST'])
@secure_endpoint()
@verify_args(['organization', 'username', 'name', 'email', 'public_key'])
def org_create():
    db = get_db()
    cur = db.cursor()

    # data parsing
    data = request.decrypted_params
    organization = data['organization']
    username = data['username']
    name = data['name']
    email = data['email']
    public_key = data['public_key']

    try:
        # create org
        cur.execute("INSERT INTO organizations (name) VALUES (?);", (organization,))
        org_id = cur.lastrowid

        # get user id
        cur.execute("SELECT id FROM subjects WHERE username=?", (username,))
        user_id = cur.fetchone()

        # check if user exists
        if user_id is None:
            cur.execute("""
                INSERT INTO 
                    subjects (username, full_name, email, public_key, org) 
                VALUES 
                    (?, ?, ?, ?, ?);"""
                , (username, name, email, public_key, org_id)
            )
            user_id = cur.lastrowid
        else:
            user_id = user_id[0]

        # update organization
        cur.execute("UPDATE organizations SET created_by = ? WHERE id = ?;", (user_id, org_id))
        
        db.commit()

        return jsonify({"id": cur.lastrowid, "organization": organization, "created_by": user_id}), 200

    except Exception as e:
        db.rollback()
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500

    finally:
        cur.close()


# session endpoints
@app.route("/session/challenge")
@secure_endpoint()
@verify_args(['username'])
def challenge():

    data = request.decrypted_params

    # check if is already generated
    if data['username'] in challenges:
        return jsonify({"nounce": base64.b64encode(challenges[data['username']]).decode('utf-8')}), 200

    # gen nonce
    nonce = data['username'].encode() + os.urandom(16)
    challenges[data['username']] = nonce
    
    return jsonify({"nounce": base64.b64encode(nonce).decode('utf-8')}), 200

@app.route("/session/create", methods=['POST'])
@secure_endpoint()
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
    data = request.decrypted_params
    cur = get_db().cursor()
    
    # data parsing
    username: str = data["username"]
    organization_name: str = data["organization"]
    signature: str = data["signature"]

    # Get organization
    cur.execute("SELECT id FROM organizations WHERE name == ?", (organization_name,))
    org_id = cur.fetchone()
    if not org_id:
        return jsonify({"error": "Internal Server Error", "message": "Organization not found"}), 404
    org_id = org_id[0]

    # Retrieve the stored public key for the username
    cur.execute("SELECT public_key, id FROM subjects WHERE username == ? AND org == ?", (username, org_id))
    res:str = cur.fetchone()
    
    if res is None:
        return jsonify({"error": "Internal Server Error", "message": "User not found within organization"}), 404

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

    # Return result
    token_info = {
        'org': org_id,
        'usr': user_id
    }

    return jsonify({"message": "Authentication successful", "session_token": write_token(token_info)}), 200


# file endpoints
@app.route("/file/upload", methods=['POST'])
@secure_endpoint()
@verify_session()
@verify_permission("DOC_NEW")
@verify_args(["name", "file_handle", "algorithm", "encryption_key", "iv", "nonce"])
def upload_file():

    # Check if the document file is part of the request
    if 'document' not in request.files:
        return jsonify({"error": "No document file provided"}), 400

    data = request.decrypted_params

    # parse JSON
    document_file = request.files['document']
    document_name = data["name"]
    file_handle = data["file_handle"]
    
    alg = data["algorithm"]
    encrypted_key = data["encryption_key"]
    iv = data["iv"]
    nonce = data["nonce"]
    
    # Session data
    ses_data = extrat_token_info(request.decrypted_headers['session'])
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

    # Save the uploaded file to the specified path
    save_path = os.path.join(REPO_PATH, file_handle)
    document_file.save(save_path)

    return jsonify({
        "status": "Document uploaded successfully",
        "document_id": doc_id,
        "file_handle": file_handle
    }), 200

@app.route("/file/list")
@secure_endpoint()
@verify_session()
def list_docs():
    # parse args
    username = request.decrypted_params.get("username", "")
    date = request.decrypted_params.get("date", "")
    date_filter_type = request.decrypted_params.get("date_filter_type", "")  # nt | ot | et

    # session data
    tk_data = extrat_token_info(request.decrypted_headers['session'])
    org_id = tk_data['org']

    # get data from db
    con = get_db()
    cur = con.cursor()

    # basic query
    query = """
        SELECT
            documents.handle AS doc_handle,
            documents.name AS doc_name,
            created_by_user.username AS created_by_username,
            deleted_by_user.username AS deleted_by_username,
            documents.created_at AS doc_created_at
        FROM
            documents
        JOIN
            subjects AS created_by_user ON documents.created_by = created_by_user.id
        LEFT JOIN
            subjects AS deleted_by_user ON documents.deleted_by = deleted_by_user.id
        WHERE
            documents.organization_id = ?
    """
    params = [org_id]

    # add optional filter for username
    if username:
        query += " AND subjects.username = ?"
        params.append(username)

    # add optional filter for date
    if date:
        # ensure date is a valid format
        try:
            filter_date = datetime.strptime(date, "%Y-%m-%d")
        except ValueError:
            return jsonify({"error": "Invalid date format. Use YYYY-MM-DD."}), 400

        # filter based on date_filter_type
        if date_filter_type == "nt":  # newer than
            query += " AND DATE(documents.created_at) >= ?"
        elif date_filter_type == "ot":  # older than
            query += " AND DATE(documents.created_at) <= ?"
        elif date_filter_type == "et":  # equal to
            query += " AND DATE(documents.created_at) = ?"
        else:
            return jsonify({"error": "Invalid date filter type. Use 'nt', 'ot', or 'et'."}), 400
    
        params.append(filter_date.date())
        

    try:
        cur.execute(query, params)
        docs = cur.fetchall()

        fields = ["handle", "name", "created_by", "deleted_by", "created_at"]
        doc_list = [
            {i: j for i, j in zip(fields, doc) if j} for doc in docs
        ]
        
        return jsonify({"status": "success", "documents": doc_list}), 200
    
    except Exception as e:
        con.rollback()
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500
    
    finally:
        cur.close()

@app.route("/file/download/<file_handle>")
@secure_endpoint()
def get_file(file_handle: str):

    file_path = os.path.join(REPO_PATH, file_handle)

    if not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404
    
    return send_file(file_path, as_attachment=True), 201

@app.route("/file/metadata", methods=['GET'])
@secure_endpoint()
@verify_session()
@verify_args(["document_name"])
def get_doc_metadata():

    doc_name = request.decrypted_params.get("document_name")

    session_data = extrat_token_info(request.decrypted_headers['session'])
    org_id = session_data['org']

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
                        d.organization_id = ?
                    """
            ,(doc_name, org_id)
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
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500
    finally:
        cur.close()

@app.route("/file/delete", methods=['PUT'])
@secure_endpoint()
@verify_session()
@verify_args(["document_name"])
def delete_file():

    doc_name = request.decrypted_params.get("document_name")

    session_data = extrat_token_info(request.decrypted_headers['session'])
    org_id = session_data['org']
    usr_id = session_data['usr']
    
    db = get_db()
    cur = db.cursor()
    
    try:
        # ensure the doc exists and belongs to the user's org
        cur.execute("""
            SELECT id, handle FROM documents
            WHERE name = ? AND organization_id = ? AND deleted_by IS NULL
        """, (doc_name, org_id))
        document = cur.fetchone()

        if not document:
            return jsonify({"error": "Document not found or already deleted"}), 404

        doc_id, handle = document

        # update the deleted_by column to indicate soft deletion
        cur.execute("""
            UPDATE documents
            SET deleted_by = ?, handle = NULL
            WHERE id = ?
        """, (usr_id, doc_id))

        # Commit the transaction
        db.commit()

        return jsonify({"status": "success", "handle": handle}), 200

    except Exception as e:
        db.rollback()
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500

    finally:
        cur.close()


# subject endpoints
@app.route("/subject/add", methods=['POST'])
@secure_endpoint()
@verify_session()
@verify_args(["username", "name", "email", 'public_key'])
def add_subject():
    session_data = extrat_token_info(request.decrypted_headers['session'])
    org_id = session_data['org']

    data = request.decrypted_params
    username = data["username"]
    name = data["name"]
    email = data["email"]
    public_key = data['public_key']

    db = get_db()
    cur = db.cursor()

    try:
        cur.execute("""
            INSERT INTO 
                subjects (username, full_name, email, public_key, org) 
            VALUES (?, ?, ?, ?, ?);
        """, (username, name, email, public_key, org_id))
        client_id = cur.lastrowid

        db.commit()

    except Exception as e:
        db.rollback()
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500

    finally:
        cur.close()
    
    return jsonify({"status": "success", "client id": client_id}), 200

@app.route("/subject/list", methods=['GET'])
@secure_endpoint()
@verify_session()
@verify_args([])
def list_subjects():
    session_data = extrat_token_info(request.decrypted_headers['session'])
    
    org_id = session_data['org']
    username = request.decrypted_params.get("username", None)

    db = get_db()
    cur = db.cursor()

    query = """
            SELECT
                username, email, full_name, status
            FROM
                subjects
            WHERE
                org = ?
    """
    params = [org_id]

    # if you give a username
    if username:
        query += " AND s.username = ?"
        params.append(username)

    try:

        cur.execute(query, params)
        results = cur.fetchall()

        subjects = [
            {
                "username": row[0],
                "email": row[1],
                "name": row[2],
                "status": "active" if row[3] else "suspended"
            }
            for row in results
        ]

        # send result
        
        if subjects:
            return jsonify({"status": "success", "subjects": subjects}), 200


        if username:
            message = f"Subject '{username}' not found."
        else:
            message = "No subjects found."

        return jsonify({"error": message}), 400
        
    except Exception as e:
        db.rollback()
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500

    finally:
        cur.close()

@app.route("/subject/suspend", methods=["PUT"])
@secure_endpoint()
@verify_session()
@verify_args(["username"])
def suspend_subject():

    session_data = extrat_token_info(request.decrypted_headers['session'])
    org_id = session_data['org']

    data = request.decrypted_params
    username = data['username']

    db = get_db()
    cur = db.cursor()

    try:

        cur.execute("""
            UPDATE subjects
            SET status = ?
            WHERE username = ? AND org = ?
        """,(False, username, org_id))

        db.commit()
        return jsonify({"status": "success", "message": f"Subject {username} has been suspended."}), 200
    
    except Exception as e:
        db.rollback()
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500
    
    finally:
        cur.close()

@app.route("/subject/activate", methods=["PUT"])
@secure_endpoint()
@verify_session()
@verify_args(["username"])
def activate_subject():

    session_data = extrat_token_info(request.decrypted_headers['session'])
    org_id = session_data['org']

    data = request.decrypted_params
    username = data['username']

    db = get_db()
    cur = db.cursor()

    try:

        cur.execute("""
            UPDATE subjects
            SET status = ?
            WHERE username = ? AND org = ?
            """,(True, username, org_id))

        db.commit()
        return jsonify({"status": "success", "message": f"Subject {username} has been activated."}), 200
    
    except Exception as e:
        db.rollback()
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500
    finally:
        cur.close()


# role / permission enpoints
@app.route("/role/add", methods=["POST"])
@secure_endpoint()
@verify_session()
@verify_args(['role'])
def add_role():
    session_data = extrat_token_info(request.decrypted_headers['session'])
    usr_id = session_data['usr']
    org_id = session_data['org']

    data = request.decrypted_params
    role = data['role']

    db = get_db()
    cur = db.cursor()

    try:

        cur.execute("""
            INSERT INTO roles (name, organization_id) VALUES
            (?, ?)
        """, (role, org_id))

        db.commit()
        return jsonify({"status": "success", "message": f"Role {role} has been added."}), 200
    
    except Exception as e:
        db.rollback()
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500
    finally:
        cur.close()

@app.route("/role/assume", methods=["POST"])
@secure_endpoint()
@verify_session()
@verify_args(['role'])
def assume_role():
    session_data = extrat_token_info(request.decrypted_headers['session'])
    usr = session_data['usr']

    data = request.decrypted_params
    role: str = data['role']

    if role in session_data.get('role', []):
        return jsonify({"status": "success", "message": "User already has that role"}), 203

    db = get_db()
    cur = db.cursor()

    try:
        cur.execute("""
            SELECT r.name
            FROM subject_roles sr
            JOIN roles r ON sr.role_id = r.id
            WHERE sr.subject_id = ? AND sr.status = TRUE;
        """, (usr,))
        subject_allowed_roles = list(map(lambda x:x[0], cur.fetchall()))

        if role.lower() not in map(str.lower, subject_allowed_roles):
            return jsonify({"error": "Subject does not have permission for this role."}), 202

        if 'role' not in session_data:
            session_data['role'] = []
        session_data['role'].append(role)
                
        db.commit()
        return jsonify({"status": "success", "session_token": write_token(session_data)}), 200
    
    except Exception as e:
        db.rollback()
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500
    finally:
        cur.close()

@app.route("/role/drop", methods=["PUT"])
@secure_endpoint()
@verify_session()
@verify_args(['role'])
def drop_role():
    session_data = extrat_token_info(request.decrypted_headers['session'])

    data = request.decrypted_params
    role: str = data['role']

    if 'role' not in session_data or role not in session_data['role']:
        return jsonify({"status": "success", "message": "User does not have that role."}), 202

    session_data['role'].remove(role)

    return jsonify({"status": "success", "session_token": write_token(session_data)}), 200

@app.route("/role/add_permission", methods=["PUT"])
@secure_endpoint()
@verify_session()
@verify_args(['role', 'target'])
def add_permission():
    session_data = extrat_token_info(request.decrypted_headers['session'])
    org_id = session_data['org']

    data = request.decrypted_params
    role: str = data['role']
    target: str = data['target']


    db = get_db()
    cur = db.cursor()

    try:
        cur.execute("SELECT id FROM permissions WHERE name = ?", (target,))
        is_permission = cur.fetchone() is None

        if is_permission:
            cur.execute("""
                INSERT INTO subject_roles (subject_id, role_id)
                VALUES (
                    (SELECT id FROM subjects WHERE username = ? AND org = ?),
                    (SELECT id FROM roles WHERE name = ? AND organization_id = ?)
                );
            """, (target, org_id, role, org_id))
            resp = jsonify({"status": "success", "message": f"User '{target}' can now be '{role}'."}), 200

        else:
            cur.execute("""
                INSERT INTO role_permissions (role_id, permission_id)
                VALUES (
                    (SELECT id FROM roles WHERE name = ? AND organization_id = ?),
                    (SELECT id FROM permissions WHERE name = ?)
                );
            """, (role, org_id, target))
            resp = jsonify({"status": "success", "message": f"Role '{role}' has now the '{target}' permission."}), 200
                
        db.commit()
        return resp
    
    except Exception as e:
        db.rollback()
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500
    
    finally:
        cur.close()

@app.route("/role/remove_permission", methods=["DELETE"])
@secure_endpoint()
@verify_session()
@verify_args(['role', 'target'])
def remove_permission():
    session_data = extrat_token_info(request.decrypted_headers['session'])
    org_id = session_data['org']

    data = request.decrypted_params
    role: str = data['role']
    target: str = data['target']


    db = get_db()
    cur = db.cursor()

    try:
        cur.execute("SELECT id FROM permissions WHERE name = ?", (target,))
        is_permission = cur.fetchone() is None

        if is_permission:
            cur.execute("""
                DELETE FROM subject_roles
                WHERE 
                    subject_id = (SELECT id FROM subjects WHERE username = ? AND org = ?) AND
                    role_id = (SELECT id FROM roles WHERE name = ? and organization_id = ?);
            """, (target, org_id, role, org_id))
            resp = jsonify({"status": "success", "message": f"User '{target}' no longer can be '{role}'."}), 200

        else:
            cur.execute("""
                DELETE FROM role_permissions
                WHERE 
                    role_id = (SELECT id FROM roles WHERE name = ? AND organization_id = ?) AND 
                    permission_id = (SELECT id FROM permissions WHERE name = ?);
            """, (role, org_id, target))
            resp = jsonify({"status": "success", "message": f"Role '{target}' no longer has the '{target}' permission."}), 200
                
        db.commit()
        return resp
    
    except Exception as e:
        db.rollback()
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500
    
    finally:
        cur.close()

@app.route("/role/list", methods=["GET"])
@secure_endpoint()
@verify_session()
def list_roles():
    session_data = extrat_token_info(request.decrypted_headers['session'])
    org = session_data['org']

    db = get_db()
    cur = db.cursor()

    try:
        cur.execute("""
            SELECT name, status
            FROM roles
            WHERE organization_id = ?;
        """, (org,))

        roles_in_org = cur.fetchall()

        payload_res = [
            {"name": row[0], "status": row[1]}
            for row in roles_in_org
        ]

        db.commit()
        return jsonify({"status": "success", "roles": payload_res}), 200
    
    except Exception as e:
        db.rollback()
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500
    
    finally:
        cur.close()

@app.route("/role/list_subjects", methods=["GET"])
@secure_endpoint()
@verify_session()
@verify_args(['role'])
def list_role_subjects():
    session_data = extrat_token_info(request.decrypted_headers['session'])
    org = session_data['org']

    data = request.decrypted_params
    role: str = data['role']

    db = get_db()
    cur = db.cursor()

    try:
        cur.execute("""
            SELECT
                s.username, 
                s.email, 
                s.full_name,
                s.status
            FROM subjects s
            JOIN subject_roles sr ON s.id = sr.subject_id
            JOIN roles r ON sr.role_id = r.id
            WHERE 
                r.name = ? AND
                s.org = ?;
        """, (role, org))

        subjects_with_role = cur.fetchall()

        payload_res = [
            {"username": row[0], "email": row[1], "full_name": row[2], "status": row[3]}
            for row in subjects_with_role
        ]

        db.commit()
        return jsonify({"status": "success", "subjects": payload_res}), 200
    
    except Exception as e:
        db.rollback()
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500
    
    finally:
        cur.close()

@app.route("/role/list_subject_roles", methods=["GET"])
@secure_endpoint()
@verify_session()
@verify_args(['username'])
def list_subject_roles():
    session_data = extrat_token_info(request.decrypted_headers['session'])
    org = session_data['org']

    data = request.decrypted_params
    username: str = data['username']

    db = get_db()
    cur = db.cursor()

    try:
        cur.execute("""
            SELECT
                r.name, 
                r.status
            FROM roles r
            JOIN subject_roles sr ON r.id = sr.role_id
            JOIN subjects s ON sr.subject_id = s.id
            WHERE 
                s.username = ? AND
                s.org = ?;
        """, (username, org))

        roles_of_subject = cur.fetchall()

        payload_res = [
            {"name": row[0], "status": row[1]}
            for row in roles_of_subject
        ]

        db.commit()
        return jsonify({"status": "success", "roles": payload_res}), 200
    
    except Exception as e:
        db.rollback()
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500
    
    finally:
        cur.close()

@app.route("/role/list_permissions", methods=["GET"])
@secure_endpoint()
@verify_session()
@verify_args(['role'])
def list_role_permissions():
    session_data = extrat_token_info(request.decrypted_headers['session'])
    org = session_data['org']

    data = request.decrypted_params
    role: str = data['role']

    db = get_db()
    cur = db.cursor()

    try:
        cur.execute("""
            SELECT
                p.name
            FROM permissions p
            JOIN role_permissions rp ON rp.permission_id = p.id
            JOIN roles r ON r.id = rp.role_id
            WHERE 
                r.name = ? AND
                r.organization_id = ?;
        """, (role, org))

        permissions_of_role = cur.fetchall()

        payload_res = [row[0] for row in permissions_of_role]

        db.commit()
        return jsonify({"status": "success", "permissions": payload_res}), 200
    
    except Exception as e:
        db.rollback()
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500
    
    finally:
        cur.close()

@app.route("/role/list_permission_roles", methods=["GET"])
@secure_endpoint()
@verify_session()
@verify_args(['permission'])
def list_permission_roles():
    session_data = extrat_token_info(request.decrypted_headers['session'])
    org = session_data['org']

    data = request.decrypted_params
    permission: str = data['permission']

    db = get_db()
    cur = db.cursor()

    try:
        cur.execute("""
            SELECT
                r.name, 
                r.status
            FROM roles r
            JOIN role_permissions rp ON rp.role_id = r.id
            JOIN permissions p ON p.id = rp.permission_id
            WHERE 
                p.name = ? AND
                r.organization_id = ?;
        """, (permission, org))

        roles_with_permission = cur.fetchall()

        payload_res = [
            {"name": row[0], "status": row[1]}
            for row in roles_with_permission
        ]

        db.commit()
        return jsonify({"status": "success", "roles": payload_res}), 200
    
    except Exception as e:
        db.rollback()
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500
    
    finally:
        cur.close()

@app.route("/role/status", methods=["PUT"])
@secure_endpoint()
@verify_session()
@verify_args(['role', 'status'])
def role_status():
    session_data = extrat_token_info(request.decrypted_headers['session'])
    org = session_data['org']

    data = request.decrypted_params
    role: str = data['role']
    status: bool = data['status']

    db = get_db()
    cur = db.cursor()

    try:
        cur.execute("""
            UPDATE roles
            SET status = ?
            WHERE name = ? and organization_id = ?;
        """, (status, role, org))

        role_status = 'now active' if status else 'no longer active'
        db.commit()
        return jsonify({"status": "success", "message": f"Role '{role}' is {role_status}"}), 200
    
    except Exception as e:
        db.rollback()
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500
    
    finally:
        cur.close()


@app.route("/ping")
def ping():
    return jsonify({"status": "up"}), 200

if __name__ == '__main__':
    app.run(debug=True)
