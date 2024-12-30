# sio_2425_project

# Group members
- Bernardo Borges (103592)
- Alexandre Regalado (124562)
- António Moreira (93279)

# **Access Control Table**

| **Area** | **#** | **ASVS Level** | **CWE** | **Verification Requirement** | **Valid?** | **Reference in Code** | **Comment** | **Tool Used/Needed** |
|-|-|-|-|-|-|-|-|-|
| **General Access Control Design**  | **4.1.1** | 1 | 602 | Verify that the application enforces access control rules on a trusted service layer, especially if client-side access control is present and bypassable. | Yes        | `verify_permission` (app.py)    | Access control is implemented server-side using decorators like `verify_permission`. No critical decisions depend on client-side logic.                           | Code Review / Testing |
|                                     | **4.1.2** | 1 | 639 | Verify that all user and data attributes and policy information used by access controls cannot be manipulated by end users unless specifically authorized. | Yes        | `extrat_token_info`, `verify_permission` (app.py)     | Role and permissions are securely extracted from JWT tokens, which are tamper-proof. Permissions are tied to database queries and validated server-side.                                | Manual Code Review                        |
|                                     | **4.1.3** | 1 | 285 | Verify the principle of least privilege exists - users should only access resources for which they possess specific authorization.                      | Partially  | `verify_permission` (app.py), Role Permissions (8)    | While roles are checked, the principle of least privilege may not be fully enforced due to manager role override and potential undefined access defaults.                               | Code Review / Testing |
|                                     | **4.1.5** | 1 | 285 | Verify that access controls fail securely, including when an exception occurs.                                                                         | Yes        | `verify_permission` (app.py)                          | In case of failure (e.g., database issues, missing permissions), access control returns errors (e.g., 401, 403). Secure fallback mechanisms are in place.                              | Code Review / Testing |
| **Operation Level Access Control** | **4.2.1** | 1 | 639 | Verify sensitive data and APIs are protected against IDOR attacks.                                                                                     | Yes        | `list_docs`, `get_doc_metadata` (app.py)              | Resources are mapped to roles and permissions via secure queries, ensuring protection against IDOR. Validations include organizational and user-specific checks.                        | Code Review / Testing |
|                                     | **4.2.2** | 1 | 352 | Verify the application enforces strong anti-CSRF mechanisms.                                                                                           | No         | Not Implemented                                  | Anti-CSRF mechanisms are absent, making endpoints vulnerable to CSRF attacks if tokens are not included in requests or validated.                                                      | Code Review / Testing  |
| **Other Access Control Considerations** | **4.3.1** | 1 | 419 | Verify administrative interfaces use multi-factor authentication (MFA).                                                                                | No         | Not Implemented                                  | No MFA is implemented for administrative interfaces, leaving them vulnerable to unauthorized access through credential compromise.                                                      | Implement MFA                             |
|                                     | **4.3.2** | 1 | 548 | Verify directory browsing is disabled, and metadata like `.git` or `.svn` is not accessible.                                                           | Yes        | Flask Deafult Configuration | By default, Flask doesn't enable directory browsing. If deployed on a secure server, sensitive files (e.g., `.git`) will not be accessible unless explicitly misconfigured. | Manual Code Review |
|                                     | **4.3.3** | 2              | 732 | Verify the application enforces additional authorization for lower value systems or segregates duties for high-value applications.                      | No         | Not Implemented                                  | No step-up or adaptive authentication is present. Adding multi-layered authentication for sensitive actions would improve security for high-value systems.                             | Code Review / Testing |

---

### Observations:
1. **Strengths**:
   - Access control relies on secure server-side mechanisms (`secure_endpoint`, `verify_permission`).
   - Sensitive data, such as session tokens, is validated and protected against tampering.
   - Role and permission mappings implemented on the database level.

2. **Weaknesses**:
   - No anti-CSRF mechanisms to prevent unauthorized API use.
   - Lack of MFA for sensitive administrative interfaces.
   - Adaptive or step-up authentication is not implemented for sensitive operations.

3. **Recommendations**:
   - Implement CSRF protection, especially for state-changing operations.
   - Introduce MFA for administrative and sensitive user operations.
   - Enforce deny-by-default policies to further align with the principle of least privilege.
