const express = require('express');
const https = require('https');
const fs = require('fs');
const crypto = require('crypto');
const axios = require('axios');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ==========================================
// THÔNG SỐ BẢO MẬT (Lấy từ biến môi trường - Giả lập hệ thống của VNPay)
// ==========================================
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || "super-secret-webhook-key"; 
const KONG_USERNAME = process.env.KONG_USERNAME || "client-id";
const KONG_SECRET = process.env.KONG_SECRET || "bi-mat-sieu-cap-vjp";
const KONG_WEBHOOK_URL = process.env.KONG_WEBHOOK_URL || 'http://kong-api:8000/api/v1/webhook/payment-success';

// ==========================================
// TRANG GIAO DIỆN THANH TOÁN CHO KHÁCH HÀNG
// ==========================================
app.get('/pay', (req, res) => {
    const { orderId, amount } = req.query;
    
    res.send(`
        <html>
        <head>
            <title>Cổng thanh toán VNPay (Sandbox)</title>
            <style>
                body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f4f7f6; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
                .card { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); text-align: center; width: 400px; }
                .btn { padding: 15px 30px; background: #007bff; color: white; border: none; border-radius: 5px; font-size: 16px; cursor: pointer; width: 100%; margin-top: 20px; font-weight: bold; }
                .btn:hover { background: #0056b3; }
                .cancel { display: block; margin-top: 15px; color: #dc3545; text-decoration: none; }
            </style>
        </head>
        <body>
            <div class="card">
                <h2>💳 CỔNG THANH TOÁN VNPAY</h2>
                <p style="color: #666;">(Môi trường giả lập có HTTPS)</p>
                <hr>
                <h3 style="margin-top: 20px;">Mã đơn hàng: <span style="color: #007bff;">#${orderId || 'Unknown'}</span></h3>
                <h3>Số tiền: <span style="color: red;">${amount ? Number(amount).toLocaleString('vi-VN') : '5,000,000'} VNĐ</span></h3>
                
                <form action="/process" method="POST">
                    <input type="hidden" name="orderId" value="${orderId}">
                    <input type="hidden" name="amount" value="${amount || 5000000}">
                    <button type="submit" class="btn">✅ XÁC NHẬN THANH TOÁN</button>
                </form>
                <a href="http://localhost:4000" class="cancel">❌ Hủy giao dịch</a>
            </div>
        </body>
        </html>
    `);
});

// ==========================================
// XỬ LÝ LOGIC KHI BẤM "XÁC NHẬN" & BẮN WEBHOOK
// ==========================================
app.post('/process', async (req, res) => {
    const { orderId, amount } = req.body;

    const payload = {
        order_id: orderId,
        transaction_id: `VNPay_${Date.now()}`,
        amount: parseInt(amount),
        status: "SUCCESS"
    };

    const rawBody = JSON.stringify(payload);

    // 1. CHỮ KÝ KONG GATEWAY
    const dateStr = new Date().toUTCString(); 
    const method = "POST";
    const path = "/api/v1/webhook/payment-success"; // Đường dẫn phải khớp với Route trên Kong
    
    const kongSigningString = `date: ${dateStr}\n${method} ${path} HTTP/1.1`;
    const kongSignature = crypto.createHmac('sha256', KONG_SECRET).update(kongSigningString).digest('base64');
    const kongAuthHeader = `hmac username="${KONG_USERNAME}", algorithm="hmac-sha256", headers="date request-line", signature="${kongSignature}"`;

    // 2. CHỮ KÝ BACKEND (Chống Replay Attack & Thay đổi Payload)
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const backendHmac = crypto.createHmac('sha256', WEBHOOK_SECRET)
                       .update(timestamp + rawBody)
                       .digest('hex');

    console.log(`[VNPay Sandbox] Đang bắn Webhook cho đơn hàng #${orderId}...`);

    try {
        await axios.post(KONG_WEBHOOK_URL, payload, {
            headers: {
                'Content-Type': 'application/json',
                'Date': dateStr,                     
                'Authorization': kongAuthHeader,     
                'x-webhook-timestamp': timestamp,    
                'x-webhook-signature': backendHmac   
            }
        });

        res.send(`
            <div style="text-align: center; font-family: Arial; margin-top: 100px;">
                <h1 style="color: #28a745;">🎉 THANH TOÁN THÀNH CÔNG!</h1>
                <p>Tiền đã trừ. Webhook mã hóa HMAC kép đã được gửi an toàn xuyên qua Kong Gateway.</p>
                <a href="http://localhost:4000" style="padding: 10px 20px; background: #007bff; color: white; text-decoration: none; border-radius: 5px; display: inline-block; margin-top: 20px;">Quay lại cửa hàng</a>
            </div>
        `);
    } catch (err) {
        console.error("Lỗi Webhook:", err.response?.data || err.message);
        res.send(`
            <h3 style="color: red; text-align: center; margin-top: 50px;">❌ Bắn Webhook thất bại: Lỗi ${err.response?.status || err.message}</h3>
            <p style="text-align: center;">Vui lòng kiểm tra Terminal của mock-vnpay để xem chi tiết.</p>
        `);
    }
});

// ==========================================
// KHỞI ĐỘNG SERVER BẰNG HTTPS
// ==========================================
const options = {
    key: fs.readFileSync('./certs/vnpay.key'),
    cert: fs.readFileSync('./certs/vnpay.crt')
};

https.createServer(options, app).listen(4001, '0.0.0.0', () => {
    console.log("💰 Mock VNPay Service running Securely on https://localhost:4001");
});