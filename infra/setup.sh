#!/bin/bash

# Dừng script ngay lập tức nếu có bất kỳ lỗi nào xảy ra
set -e

echo "🚀 BẮT ĐẦU THIẾT LẬP MÔI TRƯỜNG ĐỒ ÁN BẢO MẬT API..."
echo "======================================================="

# 1. Chuyển về thư mục gốc của dự án (project-root)
# (Giả sử bạn đang chạy script này từ bất kỳ đâu trong thư mục dự án)
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)"
cd "$PROJECT_ROOT"
echo "[OK] Đang làm việc tại thư mục: $PROJECT_ROOT"

# 2. Tạo các thư mục cần thiết nếu chưa có
echo "[*] Đang kiểm tra và tạo cấu trúc thư mục..."
mkdir -p gateway
mkdir -p idp/certs
mkdir -p tests
mkdir -p docs
echo "[OK] Cấu trúc thư mục đã sẵn sàng."

# 3. Khởi tạo file .env chứa các biến môi trường bảo mật (Secrets)
# Trong đồ án thực tế, KHÔNG BAO GIỜ hardcode password vào docker-compose.yml
ENV_FILE="infra/.env"
if [ ! -f "$ENV_FILE" ]; then
    echo "[*] Đang tạo file biến môi trường ($ENV_FILE)..."
    cat <<EOF > "$ENV_FILE"
# Keycloak Settings
KC_DB_USER=keycloak
KC_DB_PASSWORD=secure_kc_password_123
KEYCLOAK_ADMIN=admin
KEYCLOAK_ADMIN_PASSWORD=admin_super_secret

# Postgres Settings
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres_db_password
EOF
    echo "[OK] Đã tạo file .env. NHỚ: Đừng commit file này lên GitHub!"
else
    echo "[INFO] File .env đã tồn tại, bỏ qua bước tạo mới."
fi

# 4. Thiết lập môi trường Python cho các kịch bản tấn công (Tests)
echo "[*] Đang thiết lập môi trường Python ảo (venv) cho thư mục tests/..."
cd tests
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "[OK] Đã tạo Python virtual environment."
else
    echo "[INFO] Python venv đã tồn tại."
fi

# Kích hoạt venv và cài đặt thư viện
source venv/bin/activate
# Tạo file requirements.txt nếu chưa có
if [ ! -f "requirements.txt" ]; then
    echo "requests==2.31.0" > requirements.txt
fi
pip install -r requirements.txt > /dev/null 2>&1
deactivate
echo "[OK] Đã cài đặt xong các thư viện Python (requests)."
cd ..

# 5. Build và khởi động Docker
echo "======================================================="
echo "[*] Đang khởi động hạ tầng qua Docker Compose..."
# Trỏ tới file docker-compose.yml nằm trong thư mục infra/
docker-compose -f infra/docker-compose.yml --env-file infra/.env up --build -d

echo "======================================================="
echo "✅ HOÀN TẤT SETUP!"
echo "Các dịch vụ đang chạy:"
echo " - API Gateway (Kong): http://localhost:8000"
echo " - Keycloak (IdP):     http://localhost:8080"
echo " - Order Service:      (Đã bị Kong che giấu bên trong mạng nội bộ)"
echo ""
echo "Để chạy kịch bản tấn công thử nghiệm, dùng lệnh:"
echo "  source tests/venv/bin/activate && python tests/attack_bola.py"