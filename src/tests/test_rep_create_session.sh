source ./functions.sh

cd ../cli
echo "rep_create_session"

# setup
curl "http://127.0.0.1:5000/jail-house-lock" > /dev/null 2>&1
./rep_subject_credentials ola1231 user1.creds > /dev/null 2>&1
./rep_subject_credentials ola1232 user2.creds > /dev/null 2>&1
./rep_create_org sal-aveiro Alxito 'Alexandre R.' alex@sal.com user1.creds > /dev/null 2>&1
./rep_create_org cruzaders Benny 'Bernardo B.' benny@cruz.com user2.creds > /dev/null 2>&1


# normal
run_test "./rep_create_session sal-aveiro Alxito ola1231 user1.creds user1.ses" 0
run_test "./rep_create_session cruzaders Benny ola1232 user2.creds user2.ses" 0

# wrong password / creds
run_test "./rep_create_session sal-aveiro Alxito ola1232 user1.creds user1.ses" 255
run_test "./rep_create_session sal-aveiro Alxito1 ola1231 user2.creds user1.ses" 255


# user not found
run_test "./rep_create_session sal-aveiro Alxito1 ola1231 user1.creds user1.ses" 254
run_test "./rep_create_session sal-aveiro Benny ola1232 user2.creds user2.ses" 254

# org not found
run_test "./rep_create_session sal-aveiro1 Alxito ola1231 user1.creds user1.ses" 253

# auth faild in the server
run_test "./rep_create_session cruzaders Benny ola1231 user1.creds user1.ses" 252



echo ""
rm out
rm *.creds
rm *.ses
cd ../tests