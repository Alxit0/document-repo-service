# Overview

## Users
User Alxito (user1)
User Benny (user2)
User Carlos (user3)
User Dinis (user4)
User Eren (user5)
User Fran (user6)

```
./rep_subject_credentials ola121 user1.creds
./rep_subject_credentials ola122 user2.creds
./rep_subject_credentials ola123 user3.creds
./rep_subject_credentials ola124 user4.creds
./rep_subject_credentials ola125 user5.creds
./rep_subject_credentials ola126 user6.creds
```

## Org
Alxito cria organizacao 'Babel'
Listar orgs

```
./rep_create_org Babel Alxito "Alexandre R." alex@sal.com user1.creds
./rep_create_session Babel Alxito ola121 ./user1.creds ./user1_session.ses
./rep_assume_role ./user1_session.ses Manager
./rep_list_orgs
```

## Add users
Alxito add user Benny to Babel
Alxito add user Carlos to Babel
Alxito add user Dinis to Babel
Alxito add user Eren to Babel

Everyone logsin

```
./rep_add_subject ./user1_session.ses Benny "Bernardo B." bnney@sal.com ./user2.creds
./rep_add_subject ./user1_session.ses Carlos "Carlos C." carlos@sal.com ./user3.creds
./rep_add_subject ./user1_session.ses Dinis "Dinis D." dinis@sal.com ./user4.creds
./rep_add_subject ./user1_session.ses Eren "Eren Y." erem@sal.com ./user5.creds

./rep_create_session Babel Benny ola122 ./user2.creds ./user2_session.ses
./rep_create_session Babel Carlos ola123 ./user3.creds ./user3_session.ses
./rep_create_session Babel Dinis ola124 ./user4.creds ./user4_session.ses
./rep_create_session Babel Eren ola125 ./user5.creds ./user5_session.ses
```

## Roles
Alxito loggin
Alxito assumes Manager

Criar o Role de Librarian
    - DOC_ACL

Criar o Role de Contributer
    - DOC_NEW

Criar o Role de Keeper
    - SUBJECT_NEW
    - SUBJECT_DOWN
    - SUBJECT_UP

Criar o Role de Reader

Criar o Role de Professor

Alxito can be a 'Librarian'
Benny can be a 'Contributer'
Carlos can be a 'Keeper'
Dinis can be a 'Reader'
Eren can be a 'Professor'

Alxito drops Manager

```
./rep_assume_role ./user1_session.ses Manager
./rep_add_role ./user1_session.ses Librarian
./rep_add_role ./user1_session.ses Contributer
./rep_add_role ./user1_session.ses Keeper
./rep_add_role ./user1_session.ses Reader
./rep_add_role ./user1_session.ses Professor

./rep_add_permission ./user1_session.ses Librarian DOC_ACL
./rep_add_permission ./user1_session.ses Contributer DOC_NEW
./rep_add_permission ./user1_session.ses Keeper SUBJECT_NEW
./rep_add_permission ./user1_session.ses Keeper SUBJECT_DOWN
./rep_add_permission ./user1_session.ses Keeper SUBJECT_UP

./rep_add_permission ./user1_session.ses Librarian Alxito
./rep_add_permission ./user1_session.ses Contributer Benny
./rep_add_permission ./user1_session.ses Keeper Carlos
./rep_add_permission ./user1_session.ses Reader Dinis
./rep_add_permission ./user1_session.ses Professor Eren
./rep_drop_role ./user1_session.ses Manager
```

## Docs
Benny assumes Contributer
adds doc 'README.md' 
adds doc 'secure_requests.py'

Alxito assumes Librarian
Alxito adds to 'README.md' the DOC_READ to 'Reader'
Alxito adds to 'README.md' the DOC_READ to 'Professor'
Alxito adds to 'README.md' the DOC_DELETE to 'Librarian'
Alxito adds to 'secure_requests.py' the DOC_READ to 'Professor'
Alxito adds to 'secure_requests.py' the DOC_DELETE to 'Librarian'

```
./rep_assume_role ./user2_session.ses Contributer
./rep_add_doc ./user2_session.ses README.md ./README.md
./rep_add_doc ./user2_session.ses secure_requests.py ./secure_requests.py

./rep_assume_role ./user1_session.ses Librarian
./rep_acl_doc ./user1_session.ses README.md + Reader DOC_READ
./rep_acl_doc ./user1_session.ses README.md + Professor DOC_READ
./rep_acl_doc ./user1_session.ses README.md + Librarian DOC_DELETE

./rep_acl_doc ./user1_session.ses secure_requests.py + Professor DOC_READ
./rep_acl_doc ./user1_session.ses secure_requests.py + Librarian DOC_DELETE
```

## Download
Eren assumes Professor
Dinis assumes Reader

Eren can get 'README.md' and 'secure_requests.py'
Dinis can get 'README.md'
Dinis fails to get 'secure_requests.py'

```
./rep_assume_role ./user5_session.ses Professor
./rep_assume_role ./user4_session.ses Reader

./rep_get_doc_file ./user5_session.ses README.md out
./rep_get_doc_file ./user5_session.ses secure_requests.py out
./rep_get_doc_file ./user4_session.ses README.md out

./rep_get_doc_file ./user4_session.ses secure_requests.py.md out
```

## Listings
Show roles in org
Show roles with 'DOC_READ' permission
Show roles with 'DOC_NEW' permission
Show permissions of Keeper
Show Alxito with Reader role

```
./rep_list_roles ./user1_session.ses
./rep_list_permission_roles ./user1_session.ses DOC_READ
./rep_list_permission_roles ./user1_session.ses DOC_NEW
./rep_list_role_permissions ./user1_session.ses Keeper
./rep_list_subject_roles ./user2_session.ses Alxito
```

# Code

```
# setup
curl http://127.0.0.1:5000/jail-house-lock
./rep_subject_credentials ola121 user1.creds
./rep_subject_credentials ola122 user2.creds
./rep_subject_credentials ola123 user3.creds
./rep_subject_credentials ola124 user4.creds
./rep_subject_credentials ola125 user5.creds
./rep_subject_credentials ola126 user6.creds

# org
./rep_create_org Babel Alxito "Alexandre R." alex@sal.com user1.creds
./rep_create_session Babel Alxito ola121 ./user1.creds ./user1_session.ses
./rep_assume_role ./user1_session.ses Manager
./rep_list_orgs

# users
./rep_add_subject ./user1_session.ses Benny "Bernardo B." bnney@sal.com ./user2.creds
./rep_add_subject ./user1_session.ses Carlos "Carlos C." carlos@sal.com ./user3.creds
./rep_add_subject ./user1_session.ses Dinis "Dinis D." dinis@sal.com ./user4.creds
./rep_add_subject ./user1_session.ses Eren "Eren Y." erem@sal.com ./user5.creds

# loggins
./rep_create_session Babel Benny ola122 ./user2.creds ./user2_session.ses
./rep_create_session Babel Carlos ola123 ./user3.creds ./user3_session.ses
./rep_create_session Babel Dinis ola124 ./user4.creds ./user4_session.ses
./rep_create_session Babel Eren ola125 ./user5.creds ./user5_session.ses

# roles set
./rep_assume_role ./user1_session.ses Manager
./rep_add_role ./user1_session.ses Librarian
./rep_add_role ./user1_session.ses Contributer
./rep_add_role ./user1_session.ses Keeper
./rep_add_role ./user1_session.ses Reader
./rep_add_role ./user1_session.ses Professor
./rep_add_permission ./user1_session.ses Librarian DOC_ACL
./rep_add_permission ./user1_session.ses Contributer DOC_NEW
./rep_add_permission ./user1_session.ses Keeper SUBJECT_NEW
./rep_add_permission ./user1_session.ses Keeper SUBJECT_DOWN
./rep_add_permission ./user1_session.ses Keeper SUBJECT_UP
./rep_add_permission ./user1_session.ses Librarian Alxito
./rep_add_permission ./user1_session.ses Contributer Benny
./rep_add_permission ./user1_session.ses Keeper Carlos
./rep_add_permission ./user1_session.ses Reader Dinis
./rep_add_permission ./user1_session.ses Professor Eren
./rep_drop_role ./user1_session.ses Manager

# docs
./rep_assume_role ./user2_session.ses Contributer
./rep_add_doc ./user2_session.ses README.md ./README.md
./rep_add_doc ./user2_session.ses secure_requests.py ./secure_requests.py

./rep_assume_role ./user1_session.ses Librarian
./rep_acl_doc ./user1_session.ses README.md + Reader DOC_READ
./rep_acl_doc ./user1_session.ses README.md + Professor DOC_READ
./rep_acl_doc ./user1_session.ses README.md + Librarian DOC_DELETE

./rep_acl_doc ./user1_session.ses secure_requests.py + Professor DOC_READ
./rep_acl_doc ./user1_session.ses secure_requests.py + Librarian DOC_DELETE

# download
./rep_assume_role ./user5_session.ses Professor
./rep_assume_role ./user4_session.ses Reader

./rep_get_doc_file ./user5_session.ses README.md out
./rep_get_doc_file ./user5_session.ses secure_requests.py out
./rep_get_doc_file ./user4_session.ses README.md out
./rep_get_doc_file ./user4_session.ses secure_requests.py.md out

# listings
./rep_list_roles ./user1_session.ses
./rep_list_permission_roles ./user1_session.ses DOC_READ
./rep_list_permission_roles ./user1_session.ses DOC_NEW
./rep_list_role_permissions ./user1_session.ses Keeper
./rep_list_subject_roles ./user2_session.ses Alxito
```