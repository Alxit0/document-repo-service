#!/bin/bash
cd ..

#delete database file
rm api/database.db

#delete org credentials
rm cli/*_cred.json

#delete org sessions
rm cli/*_session.json

#delete sample files
rm $HOME/Documents/*_?.txt

#delete sample files
rm $HOME/Downloads/*_?_copy.txt

#delete ./sio dictory in $HOME
rm -rf $HOME/.sio