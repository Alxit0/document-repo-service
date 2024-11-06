CREATE TABLE organizations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    created_by INTEGER,  -- creator
    FOREIGN KEY (created_by) REFERENCES subjects(id)
);

CREATE TABLE subjects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    full_name TEXT,
    public_key TEXT
);

CREATE TABLE documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    handle TEXT NOT NULL UNIQUE,   -- identifier for the document
    content BLOB,                  -- binary data for file storage, if needed for Delivery 1
    
    organization_id INTEGER,
    created_by INTEGER,            -- subject id of creator
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (organization_id) REFERENCES organizations(id),
    FOREIGN KEY (created_by) REFERENCES subjects(id)
);

CREATE TABLE document_metadata (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id INTEGER NOT NULL,
    
    encryption_key TEXT NOT NULL,
    alg TEXT NOT NULL,
    iv TEXT NOT NULL,
    nonce TEXT NOT NULL,

    FOREIGN KEY (document_id) REFERENCES documents(id)
);