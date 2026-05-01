docker exec -it -e VAULT_ADDR="http://127.0.0.1:8200" vault-server vault operator init

# 1. Đăng nhập vào Vault bằng Root Token mới của bạn
docker exec -it -e VAULT_ADDR="http://127.0.0.1:8200" vault-server vault login [ROOT_TOKEN_CUA_BAN]

# 2. Bật công cụ lưu trữ (KV Engine) - Lệnh này chỉ chạy 1 lần duy nhất sau khi init
docker exec -it -e VAULT_ADDR="http://127.0.0.1:8200" vault-server vault secrets enable -path=secret kv-v2

# 3. Đưa thông tin từ file .env vào Vault
docker exec -it -e VAULT_ADDR="http://127.0.0.1:8200" vault-server vault kv put secret/order-service `
>>   ENCRYPTION_KEY="khoa_bi_mat_sieu_cap_cua_an_2026" `
>>   DATABASE_URL="postgresql://neondb_owner:npg_pqQJu6UtZCB4@ep-sparkling-meadow-a1nbvjmu-pooler.ap-southeast-1.aws.neon.tech/neondb?sslmode=verify-full" `
>>   WEBHOOK_SECRET="day-la-key-sieu-bao-mat-moi"
