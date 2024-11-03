from flask import Flask, jsonify, request
import json

from database import initialize_db, close_db, get_db

app = Flask(__name__)

# database setup
app.teardown_appcontext(close_db)
with app.app_context():
    initialize_db()

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


@app.route("/ping")
def ping():
    return json.dumps({"status": "up"})


if __name__ == '__main__':
    app.run(debug=True)