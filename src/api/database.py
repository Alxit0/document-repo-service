import sqlite3
from flask import g, current_app

DATABASE = 'database.db'
SCHEMA = 'schema.sql'

def get_db() -> sqlite3.Connection:
    """Opens a new database connection if there isn't one in the request context."""
    if 'db' in g:
        return g.db

    # init connection
    g.db = sqlite3.connect(DATABASE)
    g.db.row_factory = sqlite3.Row
    
    return g.db

def close_db(e=None):
    """Closes the database connection at the end of the request."""
    
    db = g.pop('db', None)
    if db is not None:
        db.close()

def initialize_db():
    """Initializes the database if it isn't already configured."""
    db = get_db()
    cursor = db.cursor()
    
    # Check if the 'organizations' table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='organizations'")
    table_exists = cursor.fetchone()
    
    if table_exists:
        print("Database already initialized.")
        return
    
    # Run schema SQL if the table doesn't exist
    with current_app.open_resource(SCHEMA, mode='r') as f:
        print("ola")
        db.executescript(f.read())

    db.commit()
    print("Database initialized with schema.")
