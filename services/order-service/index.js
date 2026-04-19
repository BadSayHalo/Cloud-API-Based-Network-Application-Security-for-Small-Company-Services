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
            username: jwtData.preferred_username || 'unknown',
            email: jwtData.email || `${jwtData.preferred_username}@no-email.com`,   // Lấy email từ token
            full_name: jwtData.name || jwtData.preferred_username || 'New User'     // Lấy tên từ token
        };
        next();
    } catch (error) {
        return res.status(401).json({ error: "Invalid Token format" });
    }
}

// Middleware kiểm tra quyền Admin
function requireAdminRole(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader.split(' ')[1];
    const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString('utf-8'));
    
    // Tìm role admin trong mảng realm_access
    const roles = payload.realm_access?.roles || [];
    
    if (!roles.includes('admin')) {
        console.warn(`[CẢNH BÁO] User ${req.user.username} cố tình gọi API Admin!`);
        return res.status(403).json({ error: "Forbidden: Bạn không có quyền Quản trị viên!" });
    }
    next();
}

// ==========================================
// E. API ROUTES
// ==========================================

// 1. TẠO ĐƠN HÀNG (MÃ HÓA SỐ ĐIỆN THOẠI & AUTO-SYNC USER)
app.post('/api/v1/orders', verifyUserContext, async (req, res) => {
    try {
        const { sku, item_name, unit_price, qty, customer_phone } = req.body;
        const userId = req.user.id;

        // --- BƯỚC MỚI: AUTO-SYNC USER ---
        // Kiểm tra xem User này đã tồn tại trong bảng users của PostgreSQL chưa
        const userCheck = await pool.query('SELECT id FROM users WHERE id = $1', [userId]);
        
        if (userCheck.rowCount === 0) {
            // Nếu chưa có, tự động tạo hồ sơ mới dựa trên thông tin từ Keycloak
            await pool.query(
                'INSERT INTO users (id, email, full_name) VALUES ($1, $2, $3)',
                [userId, req.user.email, req.user.full_name]
            );
            console.log(`[+] Đã tự động đồng bộ User mới từ Keycloak vào DB: ${req.user.username}`);
        }
        // --------------------------------

        // Đưa mã hóa vào trong try-catch
        const encryptedPhone = encrypt(customer_phone || "Không có SĐT");

        console.log(`[BẢO MẬT] Nhận SKU: ${sku} | SĐT gốc: ${customer_phone} ---> Đã mã hóa`);

        const query = `
            INSERT INTO orders (user_id, sku, item_name, qty, unit_price, customer_phone, order_date, status)
            VALUES ($1, $2, $3, $4, $5, $6, CURRENT_DATE, 'Pending') RETURNING id
        `;
        
        const values = [userId, sku, item_name, qty || 1, unit_price, encryptedPhone];
        const { rows } = await pool.query(query, values);

        res.status(201).json({ message: "Tạo đơn hàng thành công", order_id: rows[0].id });

    } catch (err) {
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

// 3. HOÀN TẤT HỒ SƠ NGƯỜI DÙNG (Lưu SĐT và City)
app.post('/api/v1/profile', verifyUserContext, async (req, res) => {
    try {
        const { phone, city } = req.body;
        const userId = req.user.id;

        // BẮT BUỘC: Mã hóa số điện thoại ngay tại đây
        const encryptedPhone = encrypt(phone); 

        console.log(`[BẢO MẬT] Đang mã hóa SĐT cho User: ${req.user.username}`);

        const query = `
            INSERT INTO users (id, email, full_name, phone, city)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (id) DO UPDATE 
            SET phone = EXCLUDED.phone, 
                city = EXCLUDED.city;
        `;
        
        await pool.query(query, [
            userId, 
            req.user.email, 
            req.user.full_name, 
            encryptedPhone, // Lưu chuỗi đã mã hóa
            city
        ]);

        res.status(200).json({ message: "Hồ sơ đã được mã hóa và lưu trữ an toàn!" });
    } catch (err) {
        console.error("🔥 LỖI CẬP NHẬT PROFILE:", err.message);
        res.status(500).json({ error: "Lỗi hệ thống: " + err.message });
    }
});

// 4. LẤY THÔNG TIN USER (GIẢI MÁ & MASKING)
app.get('/api/v1/profile', verifyUserContext, async (req, res) => {
    try {
        const { rows } = await pool.query('SELECT phone, city FROM users WHERE id = $1', [req.user.id]);
        
        if (rows.length > 0 && rows[0].phone) {
            // Giải mã từ DB
            const rawPhone = decrypt(rows[0].phone);
            // Masking: hiện 4 số cuối (Ví dụ: ******8888)
            const maskedPhone = rawPhone.replace(/.(?=.{4})/g, '*');
            
            return res.json({ 
                phone: maskedPhone, 
                city: rows[0].city 
            });
        }
        res.json({ phone: "Chưa có", city: "Chưa có" });
    } catch (err) {
        res.status(500).json({ error: "Lỗi lấy thông tin" });
    }
});

// ==========================================
// F. ADMIN API ROUTES (Yêu cầu Token + Quyền Admin)
// ==========================================

// 1. Lấy danh sách tất cả User
app.get('/api/v1/admin/users', verifyUserContext, requireAdminRole, async (req, res) => {
    try {
        const { rows } = await pool.query('SELECT id, email, full_name, city FROM users ORDER BY created_at DESC');
        res.status(200).json(rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// 2. Lấy đơn hàng của một User cụ thể
app.get('/api/v1/admin/orders/:userId', verifyUserContext, requireAdminRole, async (req, res) => {
    try {
        const { rows } = await pool.query('SELECT * FROM orders WHERE user_id = $1 ORDER BY order_date DESC', [req.params.userId]);
        // Tương tự, giải mã SĐT cho Admin xem
        const safeOrders = rows.map(order => ({
            ...order,
            safe_phone: decrypt(order.customer_phone) // Admin được xem SĐT đầy đủ đã giải mã
        }));
        res.status(200).json(safeOrders);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// 3. Cập nhật trạng thái thanh toán
app.patch('/api/v1/admin/orders/:orderId/payment', verifyUserContext, requireAdminRole, async (req, res) => {
    try {
        const { payment_status } = req.body; // 'Paid' hoặc 'Unpaid'
        await pool.query('UPDATE orders SET payment_status = $1 WHERE id = $2', [payment_status, req.params.orderId]);
        res.status(200).json({ message: "Cập nhật thanh toán thành công!" });
    } catch (err) { res.status(500).json({ error: err.message }); }
});
