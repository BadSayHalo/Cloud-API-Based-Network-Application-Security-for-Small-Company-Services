#!/bin/bash

echo "🚀 BẮT ĐẦU TRIỂN KHAI HỆ THỐNG SECURE E-COMMERCE MICROSERVICES 🚀"
echo "------------------------------------------------------------------"

# 1. Thông nòng mạng nội bộ (Khắc phục lỗi ETIMEDOUT và Network Blackhole)
echo "[1/5] 🔧 Đang cấu hình IP Forwarding và Tường lửa (Iptables)..."
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -P FORWARD ACCEPT
sudo iptables -F FORWARD

# 2. Dọn dẹp tàn dư của các lần chạy trước
echo "[2/5] 🧹 Đang dọn dẹp các Container và Network cũ..."
sudo docker compose -f infra/docker-compose.yml down
sudo docker network prune -f

# 3. Build và khởi chạy toàn bộ kiến trúc
echo "[3/5] 🏗️ Đang khởi tạo PostgreSQL, Keycloak, Kong và Backend..."
# Dùng --build để chắc chắn Node.js nhận code mới nhất
sudo docker compose -f infra/docker-compose.yml up -d --build --force-recreate

# 4. Đợi hệ thống Database và Node.js bắt tay nhau
echo "[4/5] ⏳ Đang chờ hệ thống ổn định nhịp tim (10 giây)..."
sleep 10

# 5. Khởi động lại Kong để chốt hạ đường truyền IP (172.17.0.1)
echo "[5/5] 🔄 Đang nạp lại định tuyến cho Kong API Gateway..."
sudo docker restart kong-api

echo "------------------------------------------------------------------"
echo "✅ TRIỂN KHAI THÀNH CÔNG! Dưới đây là trạng thái hệ thống:"
sudo docker ps -a --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

echo "------------------------------------------------------------------"
echo "🌐 BẢNG ĐIỀU KHIỂN & ENDPOINT QUAN TRỌNG:"
echo " 🔑 Keycloak IdP      : http://localhost:8080"
echo " 🛡️ Kong API Gateway  : http://localhost:8000"
echo " ⚙️ Backend Node.js   : http://localhost:3000 (Chỉ dùng nội bộ)"
echo ""
echo "🔥 Lệnh Test Nhanh (Nhớ thay <TOKEN> bằng JWT thực tế của bạn):"
echo " curl -i -H \"Authorization: Bearer <TOKEN>\" http://127.0.0.1:8000/api/v1/orders"
echo "------------------------------------------------------------------"
