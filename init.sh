mkdir ./nginx/certs/
mkdir ./keys/

openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ./nginx/certs/nginx.key -out ./nginx/certs/nginx.crt -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=selfsigned.com"

ssh-keygen -t rsa -b 4096 -f ./keys/shellinaboxKEY -N ""

mv ./keys/shellinaboxKEY.pub ./shellinabox/pubkey
