- openssl genrsa -out private.pem 2048
- openssl rsa -in private.pem -outform PEM -pubout -out public.pem

- cargo run
- `token=$(curl -s http://localhost:8080/generate_token)`
- `curl  -H "Authorization: Bearer $token" http://localhost:8080/protected`