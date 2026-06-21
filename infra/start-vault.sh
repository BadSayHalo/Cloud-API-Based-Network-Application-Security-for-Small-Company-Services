#!/bin/sh

echo "Đang giải mã Vault Key vào RAM..."

apk add --no-cache openssl

# Giải mã Vault Key vào RAM (/dev/shm/)
openssl pkey -in /vault/certs/vault.key -out /dev/shm/vault-clear.key -passin env:VAULT_KEY_PASS

echo "Khởi động Vault Server..."
# Khởi động Vault dưới dạng background
vault server -config=/vault/config/vault-config.hcl &
VAULT_PID=$!

# Đợi Vault load xong (khoảng 3 giây)
sleep 3

echo "Xóa plaintext Vault Key..."
rm -f /dev/shm/vault-clear.key

# Giữ container chạy
wait $VAULT_PID