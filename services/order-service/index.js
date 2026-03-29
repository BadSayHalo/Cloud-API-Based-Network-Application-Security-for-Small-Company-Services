const express = require('express');
const { Pool } = require('pg');
const crypto = require('crypto');

const app = express();
app.use(express.json());

// ==========================================
// 1. CẤU HÌNH KẾT NỐI POSTGRESQL (NỘI BỘ)
// ==========================================
const pool = new Pool({
    user: process.env.DB_USER || 'postgres',
    host: process.env.DB_HOST || '172.17.0.1', // Đường tắt "xuyên tường" đã setup
    database: process.env.DB_NAME || 'laptop_store',
    password: process.env.DB_PASSWORD || 'postgres_db_password',
    port: 5432,
});

pool.connect()
    .then(() => console.log('✅ Đã kết nối thành công với PostgreSQL!'))
    .catch(err => console.error('❌ Lỗi kết nối Database:', err));

// ==========================================
// 2. MODULE CRYPTO: AES-256-GCM (BẢO VỆ DỮ LIỆU TĨNH)
// ==========================================
// Tạo một khóa bí mật 32-byte (Trong thực tế sẽ dùng biến môi trường .env)
const ENCRYPTION_KEY = crypto.scryptSync('my_super_secret_key_nt219', 'salt', 32);

// Hàm mã hóa (Khóa két sắt)
function encrypt(text) {
    if (!text) return text;
    const iv = crypto.randomBytes(12); // GCM khuyên dùng IV 12 bytes
    const cipher = crypto.createCipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');
    return `${iv.toString('hex')}:${encrypted}:${authTag}`;
}

// Hàm giải mã (Mở két sắt)
function decrypt(encText) {
    if (!encText) return encText;
    try {
        const parts = encText.split(':');
        const iv = Buffer.from(parts[0], 'hex');
        const encryptedText = parts[1];
        const authTag = Buffer.from(parts[2], 'hex');
        const decipher = crypto.createDecipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
        decipher.setAuthTag(authTag);
        let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (error) {
        return "[Lỗi giải mã hoặc dữ liệu bị giả mạo]";
    }
}

// ==========================================
// 3. MIDDLEWARE XÁC THỰC (ĐỌC JWT TỪ KONG)
// ==========================================
function verifyUserContext(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader) {
        return res.status(401).json({ error: "Unauthorized - Missing Token Identity" });
    }

    try {
        // Tách chuỗi "Bearer <token>"
        const token = authHeader.split(' ')[1];
        
        // Giải mã Payload của JWT (Kong đã lo việc verify chữ ký ES256 rồi, mình chỉ việc đọc nội dung)
        const payloadBase64 = token.split('.')[1];
        const decodedPayload = Buffer.from(payloadBase64, 'base64').toString('utf-8');
        const jwtData = JSON.parse(decodedPayload);

        // Gán thông tin user vào Request. Ưu tiên lấy username (preferred_username của Keycloak)
        req.user = {
            id: jwtData.sub,
            username: jwtData.preferred_username || jwtData.sub
        };
        next();
    } catch (error) {
        return res.status(401).json({ error: "Invalid Token format" });
    }
}

// ==========================================
// 4. API ENDPOINTS (NGHIỆP VỤ & BẢO MẬT)
// ==========================================

// API TẠO ĐƠN HÀNG MỚI (Trình diễn mã hóa AES)
app.post('/api/v1/orders', verifyUserContext, async (req, res) => {
    const { laptop_name, price, customer_phone } = req.body;

    // Mã hóa số điện thoại khách hàng bằng AES-256-GCM trước khi ném vào DB
    const encryptedPhone = encrypt(customer_phone);

    try {
        // ANTI-BOLA Cấp 1: Gắn cứng owner_id là người đang đăng nhập, không cho phép gửi ID giả mạo từ Body
        const query = `
            INSERT INTO orders (owner_id, laptop_name, price, customer_phone, status)
            VALUES ($1, $2, $3, $4, 'Pending') RETURNING id
        `;
        const values = [req.user.username, laptop_name, price, encryptedPhone];
        const { rows } = await pool.query(query, values);

        res.status(201).json({
            message: "Tạo đơn hàng thành công",
            order_id: rows[0].id
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Lỗi lưu trữ cơ sở dữ liệu" });
    }
});

// API LẤY DANH SÁCH ĐƠN HÀNG (Trình diễn Anti-BOLA và DTO)
app.get('/api/v1/orders', verifyUserContext, async (req, res) => {
    try {
        // ANTI-BOLA Cấp 2: Chỉ Query ra những đơn hàng thuộc về chính User này
        const query = 'SELECT * FROM orders WHERE owner_id = $1';
        const { rows } = await pool.query(query, [req.user.username]);

        // DATA TRANSFER OBJECT (DTO) - Chống Excessive Data Exposure
        const safeOrders = rows.map(order => {
            // Giải mã điện thoại, nhưng áp dụng Masking (che giấu) để tăng cường riêng tư
            const rawPhone = decrypt(order.customer_phone);
            const maskedPhone = rawPhone ? rawPhone.slice(-4).padStart(rawPhone.length, '*') : null;

            return {
                order_id: order.id,
                product: order.laptop_name,
                price: order.price,
                status: order.status,
                phone: maskedPhone // Trả về dạng ******8888 thay vì nguyên số
            };
        });

        res.status(200).json({
            user_context: req.user.username,
            total_orders: safeOrders.length,
            data: safeOrders
        });
    } catch (err) {
        res.status(500).json({ error: "Internal Server Error" });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Order Service running on port ${PORT}`);
});
