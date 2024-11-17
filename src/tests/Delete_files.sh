#!/bin/bash

#delete database file
rm delivery?/src/api/database.db

#delete org credentials
rm delivery?/src/cli/*_cred.json

#delete org sessions
rm delivery?/src/cli/*_session.json

#delete sample files
rm $HOME/Documents/*_?.txt

#delete sample files
rm $HOME/Downloads/*_?_copy.txt