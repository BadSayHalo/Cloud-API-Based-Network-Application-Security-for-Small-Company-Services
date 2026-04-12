const express = require('express');
const { Pool } = require('pg');
const https = require('https');
const fs = require('fs');
const crypto = require('crypto'); // <-- THÊM THƯ VIỆN NÀY

const app = express();
app.use(express.json());

// ==========================================
// A. CẤU HÌNH BẢO MẬT AES-256
// ==========================================
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY; // Phải đủ 32 ký tự trong file .env
const IV_LENGTH = 16;

// Hàm Mã hóa
function encrypt(text) {
    if (!text) return null;
    let iv = crypto.randomBytes(IV_LENGTH);
    let cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(ENCRYPTION_KEY, 'utf-8'), iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    let authTag = cipher.getAuthTag().toString('hex');
    return `${iv.toString('hex')}:${encrypted}:${authTag}`;
}

// Hàm Giải mã
function decrypt(text) {
    if (!text) return null;
    try {
        let parts = text.split(':');
        let iv = Buffer.from(parts[0], 'hex');
        let encryptedText = Buffer.from(parts[1], 'hex');
        let authTag = Buffer.from(parts[2], 'hex');
        let decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(ENCRYPTION_KEY, 'utf-8'), iv);
        decipher.setAuthTag(authTag);
        let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (e) {
        return "Lỗi giải mã";
    }
}

// ==========================================
// B. CẤU HÌNH mTLS VÀ SERVER
// ==========================================
const options = {
    key: fs.readFileSync('./certs/node.key'),
    cert: fs.readFileSync('./certs/node.crt'),
    ca: [fs.readFileSync('./certs/ca.crt')],
    requestCert: true,
    rejectUnauthorized: true
};

https.createServer(options, app).listen(process.env.PORT || 3000, '0.0.0.0', () => {
    console.log('🔒 Order Service is running with mTLS (HTTPS) on port 3000!');
});

// ==========================================
// C. KẾT NỐI DATABASE (NEON CLOUD)
// ==========================================
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

pool.on('error', (err) => console.error('⚠️ Lỗi PostgreSQL:', err.message));
pool.connect()
    .then(client => {
        console.log('✅ Đã kết nối PostgreSQL thành công!');
        client.release();
    })
    .catch(e => console.error('❌ Lỗi kết nối lúc khởi động:', e));

// ==========================================
// D. BẢO VỆ VÒNG TRONG (XÁC THỰC JWT)
// ==========================================
function verifyUserContext(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ error: "Missing Token" });

    try {
        const token = authHeader.split(' ')[1];
        const payloadBase64 = token.split('.')[1];
        const jwtData = JSON.parse(Buffer.from(payloadBase64, 'base64').toString('utf-8'));

        req.user = {
            id: jwtData.sub,
            username: jwtData.preferred_username || jwtData.email || 'unknown'
        };
        next();
    } catch (error) {
        return res.status(401).json({ error: "Invalid Token format" });
    }
}

// ==========================================
// E. API ROUTES
// ==========================================

// 1. TẠO ĐƠN HÀNG (MÃ HÓA SỐ ĐIỆN THOẠI)
// 1. TẠO ĐƠN HÀNG (MÃ HÓA SỐ ĐIỆN THOẠI)
app.post('/api/v1/orders', verifyUserContext, async (req, res) => {
    try {
        const { sku, item_name, unit_price, qty, customer_phone } = req.body;
        
        // 1. Đưa mã hóa vào trong try-catch để nếu lỗi Key nó sẽ báo lỗi 500 chứ không sập server
        const encryptedPhone = encrypt(customer_phone || "Không có SĐT");

        console.log(`[BẢO MẬT] Nhận SKU: ${sku} | SĐT gốc: ${customer_phone} ---> Đã mã hóa`);

        const query = `
            INSERT INTO orders (user_id, sku, item_name, qty, unit_price, customer_phone, order_date, status)
            VALUES ($1, $2, $3, $4, $5, $6, CURRENT_DATE, 'Pending') RETURNING id
        `;
        
        const values = [req.user.id, sku, item_name, qty || 1, unit_price, encryptedPhone];
        const { rows } = await pool.query(query, values);

        res.status(201).json({ message: "Tạo đơn hàng thành công", order_id: rows[0].id });

    } catch (err) {
        // Nếu có bất kỳ lỗi gì (Lỗi mã hóa, lỗi SQL, lỗi biến...), nó sẽ nhảy vào đây
        console.error("🔥 LỖI XỬ LÝ POST:", err.message);
        res.status(500).json({ error: "Lỗi hệ thống: " + err.message });
    }
});

// 2. LẤY ĐƠN HÀNG (GIẢI MÁ VÀ MASKING DỮ LIỆU)
app.get('/api/v1/orders', verifyUserContext, async (req, res) => {
    try {
        const query = 'SELECT * FROM orders WHERE user_id = $1 ORDER BY order_date DESC';
        const { rows } = await pool.query(query, [req.user.id]);

        const safeOrders = rows.map(order => {
            // Giải mã số điện thoại từ DB
            let rawPhone = decrypt(order.customer_phone);
            // Masking (Che giấu): Chỉ hiện 4 số cuối, ví dụ ******8888
            let maskedPhone = rawPhone ? rawPhone.replace(/.(?=.{4})/g, '*') : "N/A";

            return {
                order_id: order.id, 
                sku: order.sku, 
                product: order.item_name,
                total_price: order.total_price, 
                status: order.status, 
                order_date: order.order_date,
                safe_phone: maskedPhone // Trả về số đã che
            };
        });

        res.status(200).json({ user_context: req.user.id, total_orders: safeOrders.length, data: safeOrders });
    } catch (err) {
        res.status(500).json({ error: "Internal Server Error" });
    }
});
