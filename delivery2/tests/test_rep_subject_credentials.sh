source ./functions.sh

cd ../cli
echo "rep_subject_credentials"

# setup

# normal
run_test "./rep_subject_credentials ola1231 user1.creds" 0
run_test "./rep_subject_credentials ola1232 user2.creds" 0

# just one arg
run_test "./rep_subject_credentials user3.creds" 2
run_test "./rep_subject_credentials ola1233" 2
run_test "./rep_subject_credentials "" user3.creds" 2

# switch args
run_test "./rep_subject_credentials user4.creds ola1234" 0

echo ""
rm ola123*
rm *.creds
cd ../tests
