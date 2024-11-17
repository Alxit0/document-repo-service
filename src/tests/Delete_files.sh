#!/bin/bash

#delete database file
rm src/api/database.db

#delete org credentials
rm src/cli/*_cred.json

#delete org sessions
rm src/cli/*_session.json

#delete sample files
rm $HOME/Documents/*_?.txt