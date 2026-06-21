# Cloud API-Based Network Application Security for Small Company Services

Dự án này là một prototype mô phỏng hệ thống thương mại điện tử bán laptop theo kiến trúc microservices, dành cho doanh nghiệp nhỏ. Hệ thống tập trung vào bảo mật API và triển khai multi-cloud, bao gồm Kong API Gateway, Keycloak, HashiCorp Vault, mTLS/service-to-service security, Mock VNPay, PostgreSQL cloud database và logging tập trung qua Logstash/Cloudflare Tunnel.

## Mục tiêu hệ thống

- Cung cấp giao diện web cho người dùng xem sản phẩm, đăng nhập, tạo đơn hàng và thanh toán giả lập.
- Tách hệ thống thành nhiều lớp: Edge/Gateway, Identity, Application Services, Secret Management, Payment Partner và Observability.
- Mô phỏng các cơ chế bảo mật thường gặp trong hệ thống API hiện đại: JWT/OIDC, phân quyền role, mTLS, HMAC webhook, rate limit, WAF rule và quản lý secret bằng Vault.
- Triển khai thực tế trên các VM AWS/Azure để phục vụ demo, báo cáo và kiểm thử bảo mật.

## Kiến trúc & Công nghệ

- **Frontend:** HTML/JavaScript chạy sau Nginx container.
- **API Gateway:** Kong Gateway dùng để route frontend/API, TLS termination, JWT validation, HMAC webhook, rate limit và WAF-style rules.
- **Identity Provider:** Keycloak realm `laptop-store`, client `kong-gateway`, role `user`/`admin`.
- **Backend Microservices:** Node.js/Express gồm `backend-order-api` và `backend-product-api`.
- **Secret Management:** HashiCorp Vault + Vault Agent + Consul storage.
- **Payment Partner:** Mock VNPay dùng HTTPS, ECDH handshake và HMAC webhook.
- **Database:** PostgreSQL cloud database, cấu hình truy cập được lưu trong Vault/env.
- **Observability:** Edge/Kong logs gửi về Logstash thông qua Cloudflare Tunnel.

## Endpoint chính khi demo

| Thành phần | Endpoint public/URL dùng trong demo | Ghi chú |
| --- | --- | --- |
| Web UI / Kong Gateway | `https://longle24520999.kesug.com` | Entry point chính cho người dùng |
| Product API | `https://longle24520999.kesug.com/api/v1/products` | Gọi qua Kong |
| Order API | `https://longle24520999.kesug.com/api/v1/orders` | Cần token đăng nhập |
| Profile API | `https://longle24520999.kesug.com/api/v1/profile` | Cần token đăng nhập |
| Admin API | `https://longle24520999.kesug.com/api/v1/admin/*` | Cần role admin |
| Keycloak OIDC | `https://longle24520999.kesug.com/realms/laptop-store` | Public thông qua Kong |
| Mock VNPay checkout | `https://4.194.5.44:4001/checkout` | Dùng cho thanh toán giả lập |
| Payment create | `https://longle24520999.kesug.com/api/v1/payment/create` | Tạo URL thanh toán |
| Payment webhook | `https://longle24520999.kesug.com/api/v1/webhook/payment-success` | Mock VNPay gọi về Kong |

## IP/Port triển khai AWS/Azure hiện tại

| Cloud | VM | Public IP | Service/container | Port liên quan |
| --- | --- | --- | --- | --- |
| AWS | Edge / Kong / Frontend | `32.236.138.202` | `kong-api`, `frontend-web` | Public `80`, `443`; Kong internal `8000`, `8443`; Admin API `127.0.0.1:8001` |
| AWS | Keycloak IdP | `3.25.226.76` | `keycloak-idp` | `8080` |
| AWS | App Services | `3.26.225.117` | `backend-order-api` | `3000` |
| AWS | App Services | `3.26.225.117` | `backend-product-api` | `3001` |
| AWS | App Services | `3.26.225.117` | `vault-agent` | Agent nội bộ, ghi token/cert vào shared volume |
| Azure | Vault Server | `4.193.152.48` | `vault-server` | `8200` |
| Azure | Vault Server | `4.193.152.48` | `consul-storage` | Consul storage nội bộ cho Vault |
| Azure | Mock VNPay | `4.194.5.44` | `mock-vnpay` | `4001` |
| Cloudflare | Tunnel | Không public trực tiếp Logstash | Edge logs -> Logstash | Không cần mở trực tiếp port Logstash ra Internet |

## IP nội bộ đang được Kong route tới

Các IP này là IP private trong hạ tầng cloud, dùng trong cấu hình gateway hiện tại:

| Service trong Kong | Upstream hiện tại | Mục đích |
| --- | --- | --- |
| Order API | `https://172.31.22.166:3000` | Route `/api/v1/orders`, `/api/v1/profile`, `/api/v1/admin`, payment/webhook |
| Product API | `https://172.31.22.166:3001` | Route `/api/v1/products`, `/api/v1/admin/products` |
| Keycloak | `http://172.31.4.147:8080` | Route `/realms`, OIDC, static resources |
| Logstash | qua Cloudflare Tunnel | Nhận log từ Edge/Kong |

## Cấu trúc thư mục

```text
Cloud-API-Based-Network-Application-Security-for-Small-Company-Services/
├─ certs/                 # Root CA, intermediate CA, cert mTLS, cert VNPay/Kong/Vault
├─ docs/                  # Tài liệu, topology, kịch bản demo
├─ frontend/              # Giao diện web và cấu hình Nginx
├─ gateway/               # Kong declarative config
├─ infra/                 # Docker Compose, Vault, Logstash, script hạ tầng
├─ services/
│  ├─ order-service/      # Tạo đơn hàng, profile, admin, payment/webhook
│  ├─ product-service/    # Danh mục sản phẩm, tồn kho
│  └─ mock-vnpay/         # Cổng thanh toán giả lập
└─ tests/
   ├─ pentest/            # Script kiểm thử bảo mật local/dev
   └─ vm_pentest/         # Script PowerShell kiểm thử trên VM
```

## Tài khoản demo

| Vai trò | Username | Password |
| --- | --- | --- |
| Admin | `admin` | `123456` |
| User | `buithihoa` | `123456` |
| User | `huyhoang` | `123456` |

## Luồng nghiệp vụ demo

1. Người dùng truy cập `https://longle24520999.kesug.com`.
2. Đăng nhập qua Keycloak realm `laptop-store`.
3. Frontend gọi Product API qua Kong để lấy danh sách laptop.
4. Người dùng tạo đơn hàng; Order API tra cứu SKU/tồn kho qua Product API.
5. Người dùng thanh toán; hệ thống chuyển sang Mock VNPay tại `https://4.194.5.44:4001`.
6. Mock VNPay gửi webhook về Kong tại `/api/v1/webhook/payment-success`.
7. Order API xác minh webhook và cập nhật đơn hàng sang `Paid`/`Processing`.
8. Edge/Kong logs được gửi về Logstash qua Cloudflare Tunnel để quan sát request.

## Kiểm tra nhanh trên VM

```powershell
cd D:\UIT\KY4\MMH\DoAn\aws
ssh -i ".\edge-kong-fe-key.pem" ubuntu@32.236.138.202 "hostname; docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'"
ssh -i ".\idp-keycloak-key.pem" ubuntu@3.25.226.76 "hostname; docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'"
ssh -i ".\app-services-key.pem" ubuntu@3.26.225.117 "hostname; docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'"

cd D:\UIT\KY4\MMH\DoAn\azure
ssh -i ".\vault-server-vm_key.pem" azureuser@4.193.152.48 "hostname; docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'"
ssh -i ".\mock-vnpay-vm_key.pem" azureuser@4.194.5.44 "hostname; docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'"
```

## Kiểm tra nhanh endpoint

```powershell
curl.exe -k -I https://longle24520999.kesug.com
curl.exe -k https://longle24520999.kesug.com/api/v1/products
curl.exe -k https://longle24520999.kesug.com/realms/laptop-store/.well-known/openid-configuration
curl.exe -k -I "https://4.194.5.44:4001/checkout?order_id=140&amount=17475000"
```

## Ghi chú bảo mật

- Không đưa Vault root token, AppRole secret-id, database password hoặc private key vào README/report public.
- Các giá trị như `DATABASE_URL`, `ENCRYPTION_KEY`, `WEBHOOK_SECRET`, private key và token phải nằm trong Vault, `.env` riêng hoặc secret manager.
- Các script pentest/VM evidence nằm trong `tests/vm_pentest/`; video tổng thể nên ưu tiên UI và logic nghiệp vụ, không cần lặp lại toàn bộ pentest.

