CREATE TABLE organizations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    
    name TEXT NOT NULL UNIQUE,
    created_by INTEGER,  -- creator
    active_managers DEFAULT 1
    
    FOREIGN KEY (created_by) REFERENCES subjects(id)
);

CREATE TABLE subjects ( 
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    
    username TEXT NOT NULL,
    email TEXT NOT NULL,

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

-- TABLE: Permissions
CREATE TABLE permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE -- E.g., DOC_ACL, DOC_READ, DOC_DELETE, etc.
);

-- TABLE: Roles
CREATE TABLE roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    
    name TEXT NOT NULL,               -- E.g., "Managers", "Editors"
    organization_id INTEGER NOT NULL, -- Organization to which the role belongs
    status BOOLEAN DEFAULT TRUE,      -- TRUE = Active, FALSE = Suspended
    
    FOREIGN KEY (organization_id) REFERENCES organizations(id),
    UNIQUE (organization_id, name)    -- Unique role name within an organization
);

-- default permissions
-- TABLE: Role Permissions
CREATE TABLE role_permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    
    role_id INTEGER NOT NULL,
    permission_id INTEGER NOT NULL,
    
    FOREIGN KEY (role_id) REFERENCES roles(id),
    FOREIGN KEY (permission_id) REFERENCES permissions(id),
    UNIQUE (role_id, permission_id)   -- Prevent duplicate permissions for the same role
);

-- para cada subject que roles ele pode pedir
-- TABLE: Subject Roles (Mapping Subjects to Roles)
CREATE TABLE subject_roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    
    subject_id INTEGER NOT NULL, -- Subject assuming the role
    role_id INTEGER NOT NULL,    -- Role being assigned to the subject
    
    status BOOLEAN DEFAULT TRUE, -- TRUE = Active, FALSE = Suspended
    
    FOREIGN KEY (subject_id) REFERENCES subjects(id),
    FOREIGN KEY (role_id) REFERENCES roles(id),
    UNIQUE (subject_id, role_id) -- Prevent duplicate role assignments
);

-- que permissoes cada role tem para tal doc
-- TABLE: Document ACLs (Permissions for Documents)
CREATE TABLE document_acls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    document_id INTEGER NOT NULL,
    role_id INTEGER NOT NULL,
    permission_id INTEGER NOT NULL,

    FOREIGN KEY (document_id) REFERENCES documents(id),
    FOREIGN KEY (role_id) REFERENCES roles(id),
    FOREIGN KEY (permission_id) REFERENCES permissions(id),
    UNIQUE (document_id, role_id, permission_id) -- Ensure unique permission per document and role
);

-- que permissoes cada role tem para tal org
-- TABLE: Organization ACLs (Permissions for Organization Management)
CREATE TABLE organization_acls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    
    organization_id INTEGER NOT NULL,
    role_id INTEGER NOT NULL,
    permission_id INTEGER NOT NULL,
    
    FOREIGN KEY (organization_id) REFERENCES organizations(id),
    FOREIGN KEY (role_id) REFERENCES roles(id),
    FOREIGN KEY (permission_id) REFERENCES permissions(id),
    UNIQUE (organization_id, role_id, permission_id) -- Ensure unique permission per organization and role
);

CREATE TRIGGER assign_manager_role_on_org_creation
AFTER INSERT ON organizations
BEGIN
    -- Insert the 'Manager' role for the new organization
    INSERT INTO roles (name, organization_id)
    VALUES ('Manager', NEW.id);

    -- Assign the 'Manager' role to the creator (created_by)
    INSERT INTO subject_roles (subject_id, role_id)
    SELECT NEW.created_by, roles.id
    FROM roles
    WHERE roles.name = 'Manager' AND roles.organization_id = NEW.id;

    -- Assign all permissions to the 'Manager' role
    INSERT INTO role_permissions (role_id, permission_id)
    SELECT roles.id, permissions.id
    FROM roles, permissions
    WHERE roles.name = 'Manager' AND roles.organization_id = NEW.id;
END;

ALTER TABLE organizations
ADD CONSTRAINT check_active_managers_min CHECK (active_managers >= 1);

-- Insert permissions related to document management
INSERT INTO permissions (name) VALUES 
    ('DOC_ACL'),
    ('DOC_READ'),
    ('DOC_DELETE');

-- Insert permissions related to organization management
INSERT INTO permissions (name) VALUES 
    ('ROLE_ACL'),
    ('SUBJECT_NEW'),
    ('SUBJECT_DOWN'),
    ('SUBJECT_UP'),
    ('DOC_NEW');

-- Insert permissions related to role management
INSERT INTO permissions (name) VALUES 
    ('ROLE_NEW'),
    ('ROLE_DOWN'),
    ('ROLE_UP'),
    ('ROLE_MOD');
