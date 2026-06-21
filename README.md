# Cloud API-Based Network Application Security for Small Company Services

Dự án này là một nguyên mẫu (prototype) mô phỏng hệ thống thương mại điện tử vi dịch vụ (Microservices) dành cho doanh nghiệp nhỏ, được tích hợp kiến trúc bảo mật **Zero Trust** nhiều lớp. Hệ thống bao gồm API Gateway, Identity Provider (SSO), Quản lý Bí mật (Secret Management), xác thực nội bộ (mTLS), và cơ chế bảo vệ Webhook an toàn.

## Mục lục
- [Kiến trúc & Công nghệ](#-kiến-trúc--công-nghệ)
- [Cấu trúc Thư mục](#-cấu-trúc-thư-mục)
- [Hướng dẫn Setup & Khởi chạy](#-hướng-dẫn-setup--khởi-chạy)
- [Thông tin Đăng nhập Mặc định](#-thông-tin-đăng-nhập-mặc-định)

---

## Kiến trúc & Công nghệ
* **Edge Layer:** Kong API Gateway (Routing, Rate Limiting, Custom WAF).
* **Identity Layer:** Keycloak (OAuth 2.0 / OpenID Connect, JWT cấp phát).
* **Security & PKI:** HashiCorp Vault & Vault Agent (Quản lý mTLS, mã hóa AES-GCM trên RAM, Diskless Storage).
* **Microservices (Node.js):** Order Service, Product Service, Mock VNPay (Thỏa thuận khóa ECDH & Webhook Signature).
* **Database:** PostgreSQL.
* **Monitoring:** ELK Stack (Elasticsearch, Logstash, Kibana) + Cloudflare Tunnel.

---

## Cấu trúc Thư mục

```text
📦 Cloud-API-Based-Network-Application-Security
 ┣ 📂 certs/           # Chứa các chứng chỉ Root CA, Intermediate CA và mTLS tĩnh
 ┣ 📂 frontend/        # Mã nguồn giao diện Web (HTML/JS) & cấu hình Nginx
 ┣ 📂 gateway/         # Cấu hình declarative cho Kong API Gateway (kong.yml)
 ┣ 📂 infra/           # Scripts khởi tạo, cấu hình Vault, Logstash và Docker Compose
 ┣ 📂 services/        # Mã nguồn các vi dịch vụ Backend
 ┃ ┣ 📂 order-service/ # Xử lý đơn hàng, giải mã JWT, verify HMAC Webhook
 ┃ ┣ 📂 product-service/ # Quản lý danh mục và tồn kho
 ┃ ┗ 📂 mock-vnpay/    # Cổng thanh toán giả lập (ECDH Handshake)
 ┣ 📂 tests/           # Kịch bản kiểm thử bảo mật tự động
 ┃ ┣ 📂 pentest/       # Các file JS giả lập tấn công
 ┃ ┗ 📂 vm_pentest/    # Các script PowerShell đánh giá bảo mật (WAF, BOLA, JWT, Rate Limit)
 ┗ 📜 README.md
```

## Hướng dẫn Setup & Khởi chạy
* **Bước 1: Clone dự án:** Mở terminal và tải mã nguồn về máy
```
git clone [https://github.com/BadSayHalo/Cloud-API-Based-Network-Application-Security-for-Small-Company-Services.git](https://github.com/BadSayHalo/Cloud-API-Based-Network-Application-Security-for-Small-Company-Services.git)
cd Cloud-API-Based-Network-Application-Security-for-Small-Company-Services
```
* **Bước 2: Cấp quyền thực thi:**
```
cd infra
# Cấp quyền thực thi cho các script (chỉ dùng trên Linux/Mac)
chmod +x start-vault.sh start.sh
```
* **Bước 3: Khởi chạy Container:**
```
docker compose up -d --build
```
* **Bước 4: Set up HashiCorp Vault:**
```
docker exec -e VAULT_ADDR="https://127.0.0.1:8200" -e VAULT_CACERT="/vault/certs/ca.crt" vault-server vault operator init
#Tạo ra 5 key + 1 root token (Lưu ý lưu lại)
docker exec -e VAULT_ADDR="https://127.0.0.1:8200" -e VAULT_CACERT="/vault/certs/ca.crt" vault-server vault operator unseal [KEY1]
docker exec -e VAULT_ADDR="https://127.0.0.1:8200" -e VAULT_CACERT="/vault/certs/ca.crt" vault-server vault operator unseal [KEY2]
docker exec -e VAULT_ADDR="https://127.0.0.1:8200" -e VAULT_CACERT="/vault/certs/ca.crt" vault-server vault operator unseal [KEY3]

docker exec -it vault-server /bin/sh

export VAULT_ADDR='https://127.0.0.1:8200'
export VAULT_CACERT='/vault/certs/ca-bundle.crt'
export VAULT_TOKEN='[ROOT TOKEN]'

vault secrets enable pki
vault secrets tune -max-lease-ttl=43800h pki

vault write -field=csr pki/intermediate/generate/internal \
    common_name="NT219.Q21 Dynamic Intermediate CA" \
    key_type="ec" key_bits="256" \
    > /tmp/vault-dynamic-int.csr

exit
```
* **Bước 5: Ký Chứng chỉ**
```
docker cp vault-server:/tmp/vault-dynamic-int.csr ../certs/vault-dynamic-int.csr

cd ../certs
openssl x509 -req -in vault-dynamic-int.csr \
    -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out vault-dynamic-int.crt -days 1825 \
    -extfile int-ext.cnf -extensions v3_inter
```


* **Bước 6: Nạp Chứng chỉ và Cấu hình Cấp phát tự động:**
```
docker exec -it vault-server /bin/sh

export VAULT_ADDR='https://127.0.0.1:8200'
export VAULT_CACERT='/vault/certs/ca-bundle.crt'
export VAULT_TOKEN='[ROOT TOKEN]'

vault write pki/intermediate/set-signed certificate=@/vault/certs/vault-dynamic-int.crt
vault write pki/roles/microservices \
    allowed_domains="localhost,kong-api,backend-order-api,backend-product-api" \
    allow_bare_domains=true \
    allow_subdomains=true \
    allow_ip_sans=true \
    max_ttl="168h" \
    key_type="ec" \
    key_bits="256"
```
* **Bước 7: Cấu hình approle:**
```
docker exec -it vault-server /bin/sh

export VAULT_ADDR='https://127.0.0.1:8200'
export VAULT_CACERT='/vault/certs/ca-bundle.crt'
export VAULT_TOKEN='[ROOT TOKEN]'

vault auth enable approle

vault policy write order-service-policy - <<EOF
path "pki/issue/microservices" {
  capabilities = ["create", "update"]
}
path "secret/data/order-service" {
  capabilities = ["read"]
}
EOF

vault policy write product-service-policy - <<EOF
path "pki/issue/microservices" {
  capabilities = ["create", "update"]
}
path "secret/data/product-service" {
  capabilities = ["read"]
}
EOF

vault write auth/approle/role/order-service-role \
    secret_id_ttl=0 \
    token_num_uses=0 \
    token_ttl=1h \
    token_max_ttl=4h \
    policies="order-service-policy"

vault write auth/approle/role/product-service-role \
    secret_id_ttl=0 \
    token_num_uses=0 \
    token_ttl=1h \
    token_max_ttl=4h \
    policies="product-service-policy"

vault secrets enable -path=secret kv-v2

vault kv put secret/order-service \
    DATABASE_URL="postgresql://neondb_owner:npg_pqQJu6UtZCB4@ep-sparkling-meadow-a1nbvjmu-pooler.ap-southeast-1.aws.neon.tech/neondb?sslmode=verify-full" \
    ENCRYPTION_KEY="ad8e99bb0a0d6e0c646a4732379d016e26d1e9d2af7603cfac7823e9c57be5d8"

vault kv put secret/product-service \
    DATABASE_URL="postgresql://neondb_owner:npg_pqQJu6UtZCB4@ep-sparkling-meadow-a1nbvjmu-pooler.ap-southeast-1.aws.neon.tech/neondb?sslmode=verify-full"
```

* **Bước 8: Trích xuất RoleID và SecretID:**
```
# 1. Tạo thư mục chứa ID
mkdir -p /vault/ids/order
mkdir -p /vault/ids/product

# 2. Xuất ID cho Order Service
vault read -field=role_id auth/approle/role/order-service-role > /vault/ids/order/role-id
vault write -f -field=secret_id auth/approle/role/order-service-role/secret-id > /vault/ids/order/secret-id

# 3. Xuất ID cho Product Service
vault read -field=role_id auth/approle/role/product-service-role > /vault/ids/product/role-id
vault write -f -field=secret_id auth/approle/role/product-service-role/secret-id > /vault/ids/product/secret-id
```

## Thông tin Đăng nhập Mặc định
* **Admin:** Username: admin, Password: 123456
* **User:** Username: buithihoa, Password: 123456
* **User:** Username: huyhoang, Password: 123456
