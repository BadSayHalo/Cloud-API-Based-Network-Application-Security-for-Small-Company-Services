const express = require('express');
const crypto = require('crypto');
const axios = require('axios');
const https = require('https');
const fs = require('fs');
const path = require('path'); // Bắt buộc phải có dòng này

const app = express();
app.use(express.json());

app.get('/', (req, res) => {
    res.type('html').send(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Mock VNPay</title>
  <style>
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      font-family: Arial, sans-serif;
      background: #f3f7fb;
      color: #172033;
    }
    main {
      width: min(520px, calc(100% - 40px));
      padding: 42px 34px;
      border-top: 6px solid #007bff;
      border-radius: 8px;
      background: #fff;
      box-shadow: 0 18px 45px rgba(18, 38, 63, 0.14);
      text-align: center;
    }
    h1 {
      margin: 0 0 12px;
      font-size: 34px;
      color: #007bff;
      letter-spacing: 0;
    }
    p {
      margin: 0;
      font-size: 16px;
      color: #596579;
    }
  </style>
</head>
<body>
  <main>
    <h1>Hello to Mock-VNPay</h1>
    <p>HTTPS payment simulator service is running.</p>
  </main>
</body>
</html>`);
});

// Bỏ qua check SSL tự ký
const httpsAgent = new https.Agent({ rejectUnauthorized: false });

app.get('/checkout', (req, res) => {
    // Trả file checkout.html cho trình duyệt
    res.sendFile(path.join(__dirname, 'checkout.html'));
});

// =====================================
// ROUTE XỬ LÝ THANH TOÁN & BẮN WEBHOOK
// =====================================
app.post('/simulate-success', async (req, res) => {
    let rawOrderId = req.body.order_id || req.body.orderId;
    if (rawOrderId && typeof rawOrderId === 'object') {
        rawOrderId = rawOrderId.order_id || rawOrderId.orderId || rawOrderId.id;
    }

    const order_id = Number(rawOrderId);
    if (!Number.isInteger(order_id) || order_id <= 0) {
        return res.status(400).json({ error: "Invalid order_id" });
    }

    const webhookData = { order_id, status: 'PAID', timestamp: Date.now() };

    try {
        console.log(`\n[VNPay] 1. Bắt đầu xử lý đơn hàng: ${order_id}`);

        // --- PHẦN A: BẮT TAY (HANDSHAKE) VỚI ORDER SERVICE ---
        const paymentECDH = crypto.createECDH('secp256k1');
        const paymentPubKey = paymentECDH.generateKeys('base64');

        console.log(`[VNPay] 2. Đang gửi Handshake qua Kong Gateway...`);
        const KONG_BASE_URL = process.env.KONG_BASE_URL || 'https://longle24520999.kesug.com';
        const handshakeRes = await axios.post(`${KONG_BASE_URL}/api/v1/auth/handshake`, {
            publicKey: paymentPubKey
        }, { httpsAgent });

        const orderPubKey = handshakeRes.data.publicKey;
        const handshakeId = handshakeRes.data.handshakeId;

        // Tính Shared Secret
        const sharedSecret = paymentECDH.computeSecret(orderPubKey, 'base64', 'hex');
        console.log(`[VNPay] 3. Thỏa thuận khóa thành công! Handshake ID: ${handshakeId}`);

        // --- PHẦN B: KÝ HMAC VÀ BẮN WEBHOOK QUA KONG ---
        const signature = crypto.createHmac('sha256', sharedSecret)
                                .update(JSON.stringify(webhookData))
                                .digest('hex');

        console.log(`[VNPay] 4. Đang gửi Webhook qua Kong Gateway...`);
        const KONG_URL = process.env.KONG_WEBHOOK_URL || `${KONG_BASE_URL}/api/v1/webhook/payment-success`;
        
        const webhookRes = await axios.post(KONG_URL, webhookData, {
            headers: { 
                'x-webhook-signature': signature,
                'x-handshake-id': handshakeId
            },
            httpsAgent
        });

        console.log("[VNPay] 5. Webhook báo thành công:", webhookRes.data);
        
        // CHỈNH SỬA Ở ĐÂY: Trả thêm dữ liệu demo về cho Frontend
        res.json({ 
            message: "Giao dịch thành công và đã gửi Webhook bằng ECDH!",
            demo_data: {
                handshake_id: handshakeId,
                shared_secret: sharedSecret, // Bắn Secret ra để show
                signature: signature
            }
        });

    } catch (error) {
        console.error("[VNPay] Lỗi:", error.response ? error.response.data : error.message);
        res.status(500).json({ error: "Lỗi xử lý thanh toán" });
    }
});

const PORT = process.env.PORT || 4001;
const sslOptions = {
    cert: fs.readFileSync(process.env.SSL_CERT || '/app/certs/vnpay.crt'),
    key: fs.readFileSync(process.env.SSL_KEY || '/app/certs/vnpay.key')
};

https.createServer(sslOptions, app).listen(PORT, () => {
    console.log(`Mock VNPay HTTPS running on port ${PORT}`);
});
