#!/bin/sh

echo "Đang giải mã Kong Keys vào RAM..."

# Giải mã Kong Internal Key
openssl pkey -in /certs/kong-internal.key -out /dev/shm/kong-internal-clear.key -passin env:KONG_KEY_PASS

# Giải mã Kong Public Key
openssl pkey -in /certs/kong-public.key -out /dev/shm/kong-public-clear.key -passin env:KONG_KEY_PASS

# Ép Kong sử dụng key đã giải mã trên RAM
export KONG_CLIENT_SSL_CERT_KEY=/dev/shm/kong-internal-clear.key
export KONG_SSL_CERT_KEY=/dev/shm/kong-public-clear.key

echo "Khởi động Kong Gateway..."
# Dùng exec để Kong đè lên process hiện tại, giúp Docker theo dõi log chuẩn xác
exec /docker-entrypoint.sh kong docker-start