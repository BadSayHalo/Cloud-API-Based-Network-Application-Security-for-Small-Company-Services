#!/bin/bash
echo "🚀 KHỞI ĐỘNG HỆ THỐNG CLOUD API SECURITY..."

# Xóa rác cũ (dùng -v để ép DB nạp lại file init.sql)
docker compose -f infra/docker-compose.yml down -v

# Build và chạy lại toàn bộ kiến trúc
docker compose -f infra/docker-compose.yml up -d --build

echo "⏳ Đang chờ hệ thống ổn định (10 giây)..."
sleep 10
docker restart kong-api

echo "✅ HỆ THỐNG ĐÃ SẴN SÀNG!"
echo "👉 Keycloak : http://localhost:8080"
echo "👉 Kong API : http://localhost:8000"