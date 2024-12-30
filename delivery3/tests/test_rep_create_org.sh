source ./functions.sh

cd ../cli
echo "rep_subject_credentials"

# setup
curl "http://127.0.0.1:5000/jail-house-lock" > /dev/null 2>&1
./rep_subject_credentials ola1231 user1.creds > /dev/null 2>&1
./rep_subject_credentials ola1232 user2.creds > /dev/null 2>&1
./rep_subject_credentials ola1233 user3.creds > /dev/null 2>&1

# normal
run_test "./rep_create_org sal-aveiro Alxito 'Alexandre R.' alex@sal.com user1.creds" 0
run_test "./rep_create_org cruzaders Benny 'Bernardo B.' benny@cruz.com user2.creds" 0

# same user
run_test "./rep_create_org sal-aveiro2 Alxito 'Alexandre R.' alex@sal.com user1.creds" 0

# same email
run_test "./rep_create_org sal-aveiro3 Pinto 'Goncalo P.' alex@sal.com user1.creds" 0

# org name taken
run_test "./rep_create_org sal-aveiro2 Alxito 'Alexandre R.' alex@sal.com user1.creds" 255



echo ""
rm out
rm *.creds
cd ../tests