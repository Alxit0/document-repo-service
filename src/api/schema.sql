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
    public_key TEXT,
    
    org INTEGER,

    status boolean DEFAULT True,               -- True = active, False = dead inside
    FOREIGN KEY (org) REFERENCES organizations(id),
    UNIQUE (org, username)
    UNIQUE (org, email)
);

CREATE TABLE documents (    
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    handle TEXT UNIQUE,   -- identifier for the document
    name TEXT NOT NULL UNIQUE,

    organization_id INTEGER,
    created_by INTEGER,            -- subject id of creator
    deleted_by INTEGER DEFAULT NULL,            -- subject id of deleter
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (organization_id) REFERENCES organizations(id),
    FOREIGN KEY (created_by) REFERENCES subjects(id)
    FOREIGN KEY (deleted_by) REFERENCES subjects(id)
);

CREATE TABLE document_metadata (
    document_id INTEGER PRIMARY KEY,
    
    encryption_key TEXT NOT NULL,
    alg TEXT NOT NULL,
    iv TEXT NOT NULL,
    nonce TEXT NOT NULL,

    FOREIGN KEY (document_id) REFERENCES documents(id)
);