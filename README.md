# Cloud API-Based Network Application Security for Small Company Services

Dự án này là một nguyên mẫu (prototype) mô phỏng hệ thống thương mại điện tử vi dịch vụ (Microservices) dành cho doanh nghiệp nhỏ, được tích hợp kiến trúc bảo mật **Zero Trust** nhiều lớp. Hệ thống bao gồm API Gateway, Identity Provider (SSO), Quản lý Bí mật (Secret Management), xác thực nội bộ (mTLS), và cơ chế bảo vệ Webhook an toàn.

## Mục lục
- [Kiến trúc & Công nghệ](#-kiến-trúc--công-nghệ)
- [Cấu trúc Thư mục](#-cấu-trúc-thư-mục)
- [Hướng dẫn Setup & Khởi chạy](#-hướng-dẫn-setup--khởi-chạy)
- [Thông tin Đăng nhập Mặc định](#-thông-tin-đăng-nhập-mặc-định)
- [Hướng dẫn Kiểm thử Bảo mật (Pentest)](#-hướng-dẫn-kiểm-thử-bảo-mật-pentest)

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
* **Bước 2: Khởi tạo Vault & Identity Provider:**
```
cd infra
# Cấp quyền thực thi cho các script (chỉ dùng trên Linux/Mac)
chmod +x start-vault.sh start.sh

# Chạy Docker Compose cho hạ tầng IdP (Nếu bạn tách file) hoặc dùng lệnh sau:
docker-compose up -d vault keycloak postgres
```
* **Security & PKI:** HashiCorp Vault & Vault Agent (Quản lý mTLS, mã hóa AES-GCM trên RAM, Diskless Storage).
* **Microservices (Node.js):** Order Service, Product Service, Mock VNPay (Thỏa thuận khóa ECDH & Webhook Signature).
* **Database:** PostgreSQL.
* **Monitoring:** ELK Stack (Elasticsearch, Logstash, Kibana) + Cloudflare Tunnel.
