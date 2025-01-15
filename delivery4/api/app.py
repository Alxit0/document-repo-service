import base64
import secrets
import string
from typing import List
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from datetime import datetime
from functools import wraps
import os
import dotenv
from flask import Flask, jsonify, request, send_file, g

# load env variables and generate them if needed
def gen_env_vars():
    def generate_random_string(length=256):
        characters = string.ascii_letters + string.digits + string.punctuation
        random_string = ''.join(secrets.choice(characters) for _ in range(length))
        return random_string

    # ensure file exists
    with open('./.env', 'a+'):pass

    # current variables
    current = dotenv.dotenv_values('./.env')

    # gen variable
    if 'ENCRYPTION_KEY' not in current:
        dotenv.set_key('./.env', 'ENCRYPTION_KEY', Fernet.generate_key().decode())
        print('[GEN] Generated Encryotion key ...')
    
    if 'JWT_SECRET' not in current:
        dotenv.set_key('./.env', 'JWT_SECRET', generate_random_string())
        print('[GEN] Generated JWT Secret ...')

    
    if 'PRIVATE_KEY' not in current or 'PUBLIC_KEY' not in current:
        # create keys
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()   
        )
        public_key = private_key.public_key()
        
        # gen keys
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        password = dotenv.get_key('./.env', 'ENCRYPTION_KEY')
        encryption_algorithm = serialization.BestAvailableEncryption(password.encode())
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
        dotenv.set_key('./.env', 'PRIVATE_KEY', private_key_bytes.decode())
        dotenv.set_key('./.env', 'PUBLIC_KEY', public_key_bytes.decode())
        
        # save public key
        with open('./server_public_key.pem', "wb+") as pub_file:
            pub_file.write(public_key_bytes)
        
        print('[GEN] Generated Private / Public keys ...')
gen_env_vars()
dotenv.load_dotenv()

from secure_communication import secure_endpoint, parameters, client_shared_keys, get_right_body, verify_file_handle
from database import initialize_db, close_db, get_db, REPO_PATH, DATABASE
from costum_auth import verify_token, write_token, extrat_token_info, verify_signature

app = Flask(__name__)

challenges = {}

# load enviroment
SERVER_KEY = os.getenv('ENCRYPTION_KEY').encode()
PRIVATE_KEY = os.getenv('PRIVATE_KEY').encode()
PUBLIC_KEY = os.getenv('PUBLIC_KEY').encode()
cipher_suite = Fernet(SERVER_KEY)

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
            
            # check subject status
            usr = extrat_token_info(token)['usr']
            cur = get_db().cursor()
            cur.execute("SELECT status FROM subjects WHERE id = ?", (usr,))
            stat = cur.fetchone()
            cur.close()

            if not stat:
                return jsonify({"error": "Subject not active"}), 405

            return func(*args, **kwargs)
        
        return wrapper
    
    return decorator

def verify_permission(required_permissions: List[str], choser=lambda x:0, doc_related=False):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            session_data = extrat_token_info(request.decrypted_headers['session'])
            session_roles = session_data.get('role', [])
            org = session_data['org']
            
            # print(session_roles)
            if len(session_roles) == 0:
                return jsonify({"error": "Session does not have necessary permissions"}), 402
            
            # manager has overwrite
            if 'Manager' in session_roles:
                return func(*args, **kwargs)

            target = required_permissions[choser(request.decrypted_params)]

            db = get_db()
            cur = db.cursor()
            
            try:
                if not doc_related:
                    placeholders = ', '.join(['?'] * len(session_roles))
                    cur.execute(f"""
                        SELECT p.name
                        FROM permissions p 
                        JOIN organization_acls oa ON oa.permission_id = p.id
                        JOIN roles r ON r.id = oa.role_id
                        WHERE r.name = ({placeholders}) AND r.organization_id = ?;
                    """, (*session_roles, org))
                    session_permissions = set(row[0] for row in cur.fetchall())
                else:
                    doc_name = request.decrypted_params['document_name']
                    placeholders = ', '.join(['?'] * len(session_roles))
                    cur.execute(f"""
                        SELECT
                            p.name
                        FROM roles r
                        JOIN document_acls da ON da.role_id = r.id
                        JOIN permissions p ON p.id = da.permission_id
                        JOIN documents d ON d.id = da.document_id
                        WHERE 
                            d.name = ? AND
                            r.name = ({placeholders}) AND
                            r.organization_id = ?;
                    """, (doc_name, *session_roles, org))
                    session_permissions = set(row[0] for row in cur.fetchall())
                    

                if target not in session_permissions:
                    return jsonify({"error": "Session does not have necessary permissions"}), 402

                db.commit()
                return func(*args, **kwargs)
            
            except Exception as e:
                db.rollback()
                return jsonify({"error": "Internal Server Error (VP)", "message": str(e)}), 500
            
            finally:
                cur.close()

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
        # create the user
        cur.execute("""
            INSERT INTO 
                subjects (username, full_name, email, public_key) 
            VALUES 
                (?, ?, ?, ?);"""
            , (username, name, email, public_key)
        )
        user_id = cur.lastrowid

        # create org
        cur.execute("INSERT INTO organizations (name, created_by) VALUES (?, ?);", (organization, user_id))
        org_id = cur.lastrowid

        # update user
        cur.execute("UPDATE subjects SET org = ? WHERE id = ?;", (org_id, user_id))
        
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

    # gen nonce
    nonce = data['username'].encode() + os.urandom(16)
    challenges[data['username']] = nonce

    # sign the nonce with server private key
    message = base64.b64encode(nonce).decode('utf-8')
    server_private_key = serialization.load_pem_private_key(
        os.getenv('PRIVATE_KEY').encode(),
        SERVER_KEY
    )
    signature = server_private_key.sign(
        message.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return jsonify({
        "nounce": message,
        "signature": base64.b64encode(signature).decode('utf-8')
    }), 200

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
@verify_args(["name", "file_handle", "algorithm", "encryption_key", "iv", "nonce"])
@verify_permission(["DOC_NEW"])
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
            (
                doc_id, 
                cipher_suite.encrypt(encrypted_key.encode()), 
                cipher_suite.encrypt(alg.encode()), 
                cipher_suite.encrypt(iv.encode()), 
                cipher_suite.encrypt(nonce.encode())
            )
        )

        # Save the uploaded file to the specified path
        save_path = os.path.join(REPO_PATH, file_handle)
        document_file.save(save_path)

        with open(save_path, 'rb') as file:
            content = file.read()
        
        # After saving the file, verify the file handle
        if not verify_file_handle(content, alg, encrypted_key, iv, nonce, file_handle):
            raise Exception("File handle does not match the file content")

        con.commit()
    except Exception as e:
        con.rollback()
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500
    finally:
        cur.close()

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
            filter_date = datetime.strptime(date, "%d-%m-%Y")
        except ValueError:
            return jsonify({"error": "Invalid date format. Use DD-MM-YYYY."}), 400

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
@verify_permission(["DOC_READ"], doc_related=True)
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
            "encryption_key": cipher_suite.decrypt(result[3]).decode(),
            "algorithm": cipher_suite.decrypt(result[4]).decode(),
            "iv": cipher_suite.decrypt(result[5]).decode(),
            "nonce": cipher_suite.decrypt(result[6]).decode()
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
@verify_permission(["DOC_DELETE"], doc_related=True)
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
            SELECT d.id, d.handle
            FROM documents d
            WHERE d.name = ? AND d.organization_id = ? AND d.deleted_by IS NULL
        """, (doc_name, org_id))
        document = cur.fetchone()

        if not document:
            return jsonify({"error": "Document not found or already deleted"}), 404

        doc_id = document[0]

        # update the deleted_by column to indicate soft deletion
        cur.execute("""
            UPDATE documents
            SET deleted_by = ?, handle = NULL
            WHERE id = ?
        """, (usr_id, doc_id))

        # Commit the transaction
        db.commit()

        return jsonify({
            "status": "success", 
            "handle": document[1],
            "encryption_key": document[2],
            "algorithm": document[3],
            "iv": document[4],
            "nonce": document[5]
        }), 200

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
@verify_permission(['SUBJECT_NEW'])
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
@verify_permission(['SUBJECT_DOWN'])
def suspend_subject():

    session_data = extrat_token_info(request.decrypted_headers['session'])
    org_id = session_data['org']

    data = request.decrypted_params
    username = data['username']

    db = get_db()
    cur = db.cursor()

    try:
        cur.execute("""
            SELECT r.name 
            FROM roles r 
            JOIN subject_roles sr ON r.id = sr.role_id
            JOIN subjects s ON sr.subject_id = s.id
            WHERE s.username = ?;
        """, (username,))
        roles_of_target = [i[0] for i in cur.fetchall()]

        if 'Manager' in roles_of_target:
            raise Exception("User is a Manager (cannot be suspended)")

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
@verify_permission(['SUBJECT_UP'])
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
@verify_permission(['ROLE_NEW'])
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
            WHERE sr.subject_id = ? AND r.status = TRUE;
        """, (usr,))
        subject_allowed_roles = list(map(lambda x:x[0], cur.fetchall()))
        print(subject_allowed_roles)

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
@verify_permission(['ROLE_MOD'])
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
            if target in ['DOC_READ', 'DOC_DELETE']:
                raise Exception("This permission is related to Documents")

            cur.execute("""
                INSERT INTO organization_acls (organization_id, role_id, permission_id)
                VALUES (
                    ?,
                    (SELECT id FROM roles WHERE name = ? AND organization_id = ?),
                    (SELECT id FROM permissions WHERE name = ?)
                );
            """, (org_id, role, org_id, target))

            # in case of adding a Manager
            if role == 'Manager':
                cur.execute("UPDATE organizations SET active_managers = active_managers + 1 WHERE id = ?;", (org_id,))

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
@verify_permission(['ROLE_MOD'])
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
                DELETE FROM organization_acls
                WHERE 
                    organization_id = ? AND
                    role_id = (SELECT id FROM roles WHERE name = ? AND organization_id = ?) AND 
                    permission_id = (SELECT id FROM permissions WHERE name = ?);
            """, (org_id, role, org_id, target))

            # in case of removing a Manager
            if role == 'Manager':
                cur.execute("UPDATE organizations SET active_managers = active_managers - 1 WHERE id = ?;", (org_id,))

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
            JOIN organization_acls oa ON oa.permission_id = p.id
            JOIN roles r ON r.id = oa.role_id
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
            JOIN organization_acls oa ON oa.role_id = r.id
            JOIN permissions p ON p.id = oa.permission_id
            WHERE 
                p.name = ? AND
                r.organization_id = ?;
        """, (permission, org))
        roles_with_permission = cur.fetchall()

        cur.execute("""
            SELECT
                r.name, 
                r.status,
                d.name
            FROM roles r
            JOIN document_acls da ON da.role_id = r.id
            JOIN permissions p ON p.id = da.permission_id
            JOIN documents d ON d.id = da.document_id
            WHERE 
                p.name = ? AND
                r.organization_id = ?;
        """, (permission, org))
        roles_with_permission_doc = cur.fetchall()

        payload_res = [
            {"name": row[0], "status": row[1]}
            for row in roles_with_permission
        ]
        payload_res.extend([
            {"name": row[0], "status": row[1], "doc":row[2]}
            for row in roles_with_permission_doc
        ])

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
@verify_permission(['ROLE_DOWN', 'ROLE_UP'], choser=lambda x: x['status'] == True)
def role_status():
    session_data = extrat_token_info(request.decrypted_headers['session'])
    org = session_data['org']

    data = request.decrypted_params
    role: str = data['role']
    status: bool = data['status']

    if role == 'Manager':
        return jsonify({"error": "Internal Server Error", "message": "The status of 'Manager' is always active"})

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

@app.route("/role/acl_doc/add", methods=["PUT"])
@secure_endpoint()
@verify_session()
@verify_args(['document_name', 'role', 'permission'])
@verify_permission(['DOC_ACL'])
def acl_doc_add():
    session_data = extrat_token_info(request.decrypted_headers['session'])
    org = session_data['org']

    data = request.decrypted_params
    document_name: str = data['document_name']
    role: str = data['role']
    permission: bool = data['permission']

    db = get_db()
    cur = db.cursor()

    try:
        cur.execute("""
            INSERT INTO document_acls (document_id, role_id, permission_id)
            VALUES (
                (SELECT id FROM documents WHERE name = ? AND organization_id = ?),
                (SELECT id FROM roles WHERE name = ? AND organization_id = ?),
                (SELECT id FROM permissions WHERE name = ?)
            );
        """, (document_name, org, role, org, permission))

        db.commit()
        return jsonify({"status": "success", "message": f"Role '{role}' has now the '{permission}' permission for '{document_name}' document."}), 200
    
    except Exception as e:
        db.rollback()
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500
    
    finally:
        cur.close()

@app.route("/role/acl_doc/remove", methods=["DELETE"])
@secure_endpoint()
@verify_session()
@verify_args(['document_name', 'role', 'permission'])
@verify_permission(['DOC_ACL'])
def acl_doc_remove():
    session_data = extrat_token_info(request.decrypted_headers['session'])
    org = session_data['org']

    data = request.decrypted_params
    document_name: str = data['document_name']
    role: str = data['role']
    permission: bool = data['permission']

    db = get_db()
    cur = db.cursor()

    try:
        cur.execute("""
            DELETE FROM document_acls
            WHERE 
                document_id = (SELECT id FROM documents WHERE name = ? AND organization_id = ?) AND
                role_id = (SELECT id FROM roles WHERE name = ? AND organization_id = ?) AND 
                permission_id = (SELECT id FROM permissions WHERE name = ?);
        """, (document_name, org, role, org, permission))

        db.commit()
        return jsonify({"status": "success", "message": f"Role '{role}' no longer has the '{permission}' permission for '{document_name}' document."}), 200
    
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
