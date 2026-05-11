const express = require('express');
const { Pool } = require('pg');
const https = require('https');
const fs = require('fs');
const crypto = require('crypto');
const axios = require('axios'); // <-- Cần cài đặt: npm install axios
const { send } = require('process');

const app = express();
app.use(express.json({
    limit: '5mb', 
    verify: (req, res, buf) => {
        req.rawBody = buf; // Bắt lấy raw body trước khi Express biến nó thành JSON
    }
})); // Tăng giới hạn kích thước body để tránh lỗi khi gửi nhiều dữ liệu

// ==========================================
// A. CẤU HÌNH VAULT & BIẾN TOÀN CỤC
// ==========================================
const VAULT_ADDR = process.env.VAULT_ADDR || 'http://vault-server:8200';
const VAULT_TOKEN = process.env.VAULT_TOKEN || 'my-root-token';
let ENCRYPTION_KEY = ""; // Sẽ được nạp từ Vault 
const IV_LENGTH = 16;

// ==========================================
// B. HÀM LẤY SECRETS TỪ HASHICORP VAULT 
// ==========================================
async function getSecretsFromVault() {
    const tokenPath = '/app/vault-token-share/.vault-token';
    
    // Đợi tối đa 10 giây cho đến khi Agent ghi xong file token
    for (let i = 0; i < 10; i++) {
        if (fs.existsSync(tokenPath)) break;
        console.log("⏳ Dang doi Vault Agent cap Token...");
        await new Promise(res => setTimeout(res, 1000));
    }

    try {
        const VAULT_TOKEN = fs.readFileSync(tokenPath, 'utf8').trim();
        
        const response = await axios.get(`${VAULT_ADDR}/v1/secret/data/order-service`, {
            headers: { 'X-Vault-Token': VAULT_TOKEN }
        });

        // TRÍCH XUẤT ĐÚNG TÊN BIẾN TRONG VAULT
        const vaultData = response.data.data.data;
        
        return {
            key: vaultData.ENCRYPTION_KEY, // Map lai cho dung voi bootstrap
            dbUrl: vaultData.DATABASE_URL,
            webhookSecret: vaultData.WEBHOOK_SECRET
        };
    } catch (error) {
        console.error("❌ [VAULT] Loi lay secret:", error.message);
        // Fallback tra ve object rong thay vi undefined de tranh crash
        return { key: null, dbUrl: null, webhookSecret: null };
    }
}

// ==========================================
// HÀM GỬI LOG SANG ELK (LOGSTASH)
// ==========================================
async function sendLog(level, action, message, req = null) {
    const logData = {
        timestamp: new Date().toISOString(),
        service: "order-service",
        level: level,       // INFO, WARN, ERROR, CRITICAL
        action: action,     // Ví dụ: CREATE_ORDER, CANCEL_ORDER, BOLA_ATTACK
        message: message,
        user_id: req && req.user ? req.user.id : "anonymous",
        ip_address: req ? (req.headers['x-forwarded-for'] || req.socket.remoteAddress) : "N/A"
    };

    try {
        // Gửi qua HTTP input của Logstash (Cổng 5044)
        await axios.post('http://logstash:5044', logData);
    } catch (err) {
        console.error("⚠️ Không thể kết nối tới ELK Stack!");
    }
}

// ==========================================
// C. CÁC HÀM MÃ HÓA (AES-256-GCM) 
// ==========================================
function encrypt(text) {
    if (!text || !ENCRYPTION_KEY) return null;
    let iv = crypto.randomBytes(IV_LENGTH);
    let cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(ENCRYPTION_KEY, 'utf-8'), iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    let authTag = cipher.getAuthTag().toString('hex');
    return `${iv.toString('hex')}:${encrypted}:${authTag}`;
}

function decrypt(text) {
    if (!text || !ENCRYPTION_KEY) return null;
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
    } catch (e) { return "Lỗi giải mã"; }
}

// ==========================================
// D. XÁC THỰC (JWT & HMAC)
// ==========================================
function verifyUserContext(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ error: "Missing Token" });
    try {
        const token = authHeader.split(' ')[1];
        const payloadBase64 = token.split('.')[1];
        const jwtData = JSON.parse(Buffer.from(payloadBase64, 'base64').toString('utf-8'));
        req.user = { id: jwtData.sub, username: jwtData.preferred_username || 'unknown', 
                    roles: jwtData.realm_access ? jwtData.realm_access.roles : [] };
        next();
    } catch (error) { return res.status(401).json({ error: "Invalid Token" }); }
}

function verifyHMACSignature(req, res, next) {
    const signature = req.headers['x-webhook-signature'];
    const timestamp = req.headers['x-webhook-timestamp'];
    const secret = process.env.WEBHOOK_SECRET;

    if (!secret) return res.status(500).json({ error: "Webhook Secret is missing!" });

    const now = Math.floor(Date.now() / 1000);
    if (!timestamp || Math.abs(now - timestamp) > 300) {
        return res.status(401).json({ error: "Request expired (Replay Attack detected)" });
    }

    // SỬA ĐIỂM 2: Dùng req.rawBody thay vì JSON.stringify
    // Nếu request không có body thì fallback về chuỗi rỗng
    const rawBodyString = req.rawBody ? req.rawBody.toString('utf8') : '';
    
    const hmac = crypto.createHmac('sha256', secret)
                       .update(timestamp + rawBodyString)
                       .digest('hex');

    if (signature && crypto.timingSafeEqual(Buffer.from(hmac), Buffer.from(signature))) {
        next();
    } else {
        res.status(401).json({ error: "Invalid HMAC Signature!" });
    }
}

// ==========================================
// E. API ROUTES
// ==========================================
// 1. Tạo Agent để gọi HTTPS nội bộ (Dùng certs đã có)
const internalHttpsAgent = new https.Agent({
    key: fs.readFileSync('./certs/node.key'),
    cert: fs.readFileSync('./certs/node.crt'),
    ca: fs.readFileSync('./certs/ca.crt'),
    checkServerIdentity: () => undefined, // Bỏ qua hostname check vì chúng ta gọi bằng tên service trong Docker
    rejectUnauthorized: true // Bắt buộc kiểm tra chứng chỉ của Product Service
});

app.post('/api/v1/orders', verifyUserContext, async (req, res) => {
    try {
        // CHÚ Ý: Cố tình KHÔNG LẤY unit_price và item_name từ req.body nữa!
        const { sku, qty, customer_phone } = req.body;
        
        // 🛡️ BẢO MẬT 2: Data Validation 
        if (!sku) {
            return res.status(400).json({ error: "Thiếu mã sản phẩm (SKU)!" });
        }
        if (Number(qty) <= 0) {
            sendLog("CRITICAL", "BUSINESS_LOGIC_ATTACK", `User ${req.user.id} truyền số lượng âm!`, req);
            return res.status(400).json({ error: "Số lượng phải > 0!" });
        }
        
        // 🛡️ BẢO MẬT GIAO TIẾP (East-West Traffic): Lấy giá chuẩn từ Product Service
        let productData;
        try {
            const productRes = await axios.get(
                `https://backend-product-api:3001/api/v1/products/${sku}`,
                { httpsAgent: internalHttpsAgent }
            );
            productData = productRes.data.data; // Lấy được name và price thật từ Cloud DB của Product
        } catch (err) {
            return res.status(404).json({ error: "Sản phẩm không tồn tại trong hệ thống!" });
        }

        // BƯỚC QUAN TRỌNG: Gọi Product Service để TRỪ KHO
        try {
            await axios.patch(
                `https://backend-product-api:3001/api/v1/products/${sku}/reduce-stock`,
                { qty: qty || 1 },
                { httpsAgent: internalHttpsAgent }
            );
        } catch (err) {
            return res.status(400).json({ error: "Số lượng tồn kho không đủ để đặt hàng!" });
        }

        // Tạo đơn hàng với TÊN và GIÁ lấy từ Product Service (Bảo mật 100%)
        const encryptedPhone = encrypt(customer_phone || "Không có SĐT");
        const query = `
            INSERT INTO orders (user_id, sku, item_name, qty, unit_price, customer_phone, order_date, status)
            VALUES ($1, $2, $3, $4, $5, $6, CURRENT_DATE, 'Pending') RETURNING id
        `;
        // Truyền productData.name và productData.price vào thay vì lấy từ Frontend
        const values = [req.user.id, sku, productData.name, qty || 1, productData.price, encryptedPhone];
        const { rows } = await pool.query(query, values);
        
        res.status(201).json({ message: "Tạo đơn hàng thành công", order_id: rows[0].id });
        sendLog("INFO", "ORDER_CREATED", `Người dùng ${req.user.id} đã tạo đơn hàng #${rows[0].id}.`, req);
    } catch (err) {
        sendLog("ERROR", "SYSTEM_ERROR", err.message, req);
        res.status(500).json({ error: "Lỗi hệ thống: " + err.message });
    }
});

app.get('/api/v1/orders', verifyUserContext, async (req, res) => {
    try {
        const query = 'SELECT * FROM orders WHERE user_id = $1 ORDER BY order_date DESC';
        const { rows } = await pool.query(query, [req.user.id]);
        const safeOrders = rows.map(order => ({
            order_id: order.id, 
            sku: order.sku, 
            product: order.item_name,
            qty: order.qty,
            unit_price: order.unit_price,
            safe_phone: decrypt(order.customer_phone)?.replace(/.(?=.{4})/g, '*') || "N/A",
            status: order.status || 'Pending',
            payment_status: order.payment_status || 'Unpaid'
        }));
        res.status(200).json({ data: safeOrders });
        sendLog("INFO", "ORDERS_FETCHED", `Người dùng ${req.user.id} đã lấy danh sách đơn hàng.`, req);
    } catch (err) { 
        sendLog("ERROR", "SYSTEM_ERROR", err.message, req);
        res.status(500).json({ error: "Internal Error" }); 
    }
});

// User tự hủy đơn hàng của chính mình
app.patch('/api/v1/orders/:orderId/cancel', verifyUserContext, async (req, res) => {
    try {
        // 1. CHỐNG BOLA: Phải Select thêm 'sku' và 'qty' để biết đường hoàn kho
        const checkQuery = 'SELECT status, sku, qty FROM orders WHERE id = $1 AND user_id = $2';
        const { rows } = await pool.query(checkQuery, [req.params.orderId, req.user.id]);
        
        // 2. Kiểm tra tồn tại và quyền sở hữu
        if (rows.length === 0) {
            sendLog("CRITICAL", "BOLA_ATTACK_ATTEMPT", `User ${req.user.id} cố gắng hủy đơn ${req.params.orderId} của người khác!`, req);
            return res.status(404).json({ error: "Không tìm thấy đơn hàng hoặc bạn không có quyền hủy!" });
        }
        
        const order = rows[0];

        // 3. Kiểm tra điều kiện trạng thái 
        if (order.status !== 'Pending' && order.status !== 'Unpaid') {
            return res.status(400).json({ error: `Không thể hủy! Đơn hàng đang ở trạng thái: ${order.status}` });
        }

        // BƯỚC QUAN TRỌNG: Gọi Product Service để CỘNG LẠI KHO
        try {
            await axios.patch(
                `https://backend-product-api:3001/api/v1/products/${order.sku}/add-stock`,
                { qty: order.qty },
                { httpsAgent: internalHttpsAgent }
            );
        } catch (err) {
            console.error("Lỗi hoàn kho:", err.message);
            // Vẫn tiếp tục hủy đơn dù lỗi hoàn kho (Hoặc bạn có thể return lỗi tùy business logic)
        }

        // 4. Tiến hành cập nhật trạng thái hủy
        const updateQuery = "UPDATE orders SET status = 'Cancelled' WHERE id = $1";
        await pool.query(updateQuery, [req.params.orderId]);
        
        sendLog("INFO", "ORDER_CANCELLED", `Đơn hàng ${req.params.orderId} đã hủy và hoàn lại ${order.qty} sản phẩm.`, req);
        res.json({ message: `Đã hủy thành công đơn hàng #${req.params.orderId} và hoàn kho.` });
    } catch (err) {
        sendLog("ERROR", "SYSTEM_ERROR", err.message, req);
        res.status(500).json({ error: "Lỗi hệ thống: " + err.message });
    }
});

// User xác nhận đã nhận hàng
app.patch('/api/v1/orders/:orderId/deliver', verifyUserContext, async (req, res) => {
    try {
        // 1. CHỐNG BOLA: Tìm đơn hàng của ĐÚNG user này
        const checkQuery = 'SELECT status, payment_status FROM orders WHERE id = $1 AND user_id = $2';
        const { rows } = await pool.query(checkQuery, [req.params.orderId, req.user.id]);
        
        if (rows.length === 0) {
            sendLog("CRITICAL", "BOLA_ATTACK_ATTEMPT", `User ${req.user.id} cố gắng xác nhận đơn hàng ${req.params.orderId} không thuộc sở hữu!`, req);
            return res.status(404).json({ error: "Không tìm thấy đơn hàng của bạn!" });
        }
        
        const order = rows[0];

        // 2. Kiểm tra điều kiện (Phải là Processing VÀ Paid)
        if (order.status !== 'Processing' || order.payment_status !== 'Paid') {
            return res.status(400).json({ 
                error: `Chưa thể xác nhận! Đơn hàng đang ở trạng thái: ${order.status} và Thanh toán: ${order.payment_status}` 
            });
        }

        // 3. Tiến hành cập nhật
        const updateQuery = "UPDATE orders SET status = 'Delivered' WHERE id = $1";
        await pool.query(updateQuery, [req.params.orderId]);
        
        sendLog("INFO", "ORDER_DELIVERED", `Đơn hàng ${req.params.orderId} đã được giao thành công.`, req);
        res.json({ message: `Cảm ơn bạn! Đơn hàng #${req.params.orderId} đã được giao thành công.` });
    } catch (err) {
        sendLog("ERROR", "SYSTEM_ERROR", err.message, req);
        res.status(500).json({ error: "Lỗi hệ thống: " + err.message });
    }
});

app.post('/api/v1/profile', verifyUserContext, async (req, res) => {
    try {
        const { phone, city } = req.body;
        
        // 1. Kiểm tra đầu vào
        if (!phone || !city) {
            return res.status(400).json({ error: "Vui lòng điền đủ Số điện thoại và Thành phố!" });
        }

        // 2. Mã hóa Số điện thoại bằng AES-256-GCM
        const encryptedPhone = encrypt(phone);

        // 3. Cập nhật vào bảng users (Giả định bạn đã tạo bảng users)
        // Nếu DB của bạn chưa có các cột này, bạn có thể comment lệnh SQL lại để test flow mã hóa trước
        const query = `
            UPDATE users 
            SET phone = $1, city = $2 
            WHERE id = $3
        `;
        await pool.query(query, [encryptedPhone, city, req.user.id]);
        
        // 4. Ghi log cảnh báo giám sát
        sendLog("INFO", "PROFILE_UPDATED", `User ${req.user.id} đã cập nhật hồ sơ (Đã mã hóa AES)`, req);
        
        res.status(200).json({ message: "Đã lưu và mã hóa thông tin hồ sơ an toàn!" });
    } catch (err) {
        sendLog("ERROR", "SYSTEM_ERROR", err.message, req);
        res.status(500).json({ error: "Lỗi hệ thống: " + err.message });
    }
});

// 3. ADMIN: Lấy danh sách Users (Nối đúng kiểu UUID)
app.get('/api/v1/admin/users', verifyUserContext, async (req, res) => {
    if (!req.user.roles.includes('admin')) return res.status(403).json({ error: "Yêu cầu quyền Admin!" });
    try {
        // Bỏ ::text đi vì cả 2 cột đều đã là kiểu UUID chuẩn
        const query = `
            SELECT DISTINCT o.user_id, u.full_name, u.email 
            FROM orders o
            LEFT JOIN users u ON o.user_id = u.id
        `;
        const { rows } = await pool.query(query);
        
        const users = rows.map(r => ({
            id: r.user_id,
            // Lấy trực tiếp data từ DB, không chế cháo thêm gì nữa
            full_name: r.full_name || "Chưa cập nhật tên", 
            email: r.email || "Chưa cập nhật email"
        }));
        
        res.json(users);
    } catch (err) { 
        console.error("Lỗi lấy danh sách user:", err);
        res.status(500).json({ error: err.message }); 
    }
});

// 4. ADMIN: Xem chi tiết đơn hàng của 1 User (Giải mã FULL SĐT)
app.get('/api/v1/admin/orders/:userId', verifyUserContext, async (req, res) => {
    if (!req.user.roles.includes('admin')) return res.status(403).json({ error: "Forbidden" });
    try {
        const query = 'SELECT * FROM orders WHERE user_id = $1 ORDER BY order_date DESC';
        const { rows } = await pool.query(query, [req.params.userId]);
        const fullOrders = rows.map(order => ({
            id: order.id,
            item_name: order.item_name,
            qty: order.qty,
            customer_phone: decrypt(order.customer_phone), // KHÔNG CHE DẤU *
            payment_status: order.payment_status || 'Unpaid'
        }));
        res.json(fullOrders);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// 5. ADMIN: Cập nhật thanh toán
app.patch('/api/v1/admin/orders/:orderId/payment', verifyUserContext, async (req, res) => {
    if (!req.user.roles.includes('admin')) return res.status(403).json({ error: "Forbidden" });
    try {
        const { payment_status } = req.body;
        // 🛡️ BẢO MẬT 3: Chống Mass Assignment / Enum Manipulation
        // Ngăn chặn admin (hoặc hacker chiếm quyền) truyền vào một trạng thái chế bậy bạ như "HACKED" hoặc "DELETED"
        const allowedStatuses = ['Paid', 'Unpaid', 'Refunded'];
        if (!allowedStatuses.includes(payment_status)) {
            sendLog("WARN", "INVALID_DATA_ATTACK", `Thử nghiệm cập nhật trạng thái ảo: ${payment_status}`, req);
            return res.status(400).json({ error: "Trạng thái thanh toán không hợp lệ!" });
        }

        // Nếu admin duyệt "Paid", tự động chuyển status thành "Processing"
        if (payment_status === 'Paid') {
            await pool.query("UPDATE orders SET payment_status = 'Paid', status = 'Processing' WHERE id = $1", [req.params.orderId]);
        } else {
            await pool.query("UPDATE orders SET payment_status = $1 WHERE id = $2", [payment_status, req.params.orderId]);
        }
        res.json({ message: "Cập nhật thành công!" });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// API Webhook dành riêng cho Đối tác (Ví dụ: Cổng thanh toán gọi về)
// KHÔNG dùng verifyUserContext ở đây, mà dùng verifyHMACSignature
app.post('/api/v1/webhook/payment-success', verifyHMACSignature, async (req, res) => {
    try {
        const { order_id, transaction_id } = req.body;
        
        // Cập nhật trạng thái đơn hàng thành Paid
        await pool.query("UPDATE orders SET payment_status = 'Paid', status = 'Processing' WHERE id = $1", [order_id]);
        
        sendLog("INFO", "WEBHOOK_PAYMENT_SUCCESS", `Webhook xác nhận thanh toán cho đơn ${order_id} (Txn: ${transaction_id})`, req);
        res.status(200).json({ message: "Webhook processed successfully" });
    } catch (err) {
        sendLog("ERROR", "WEBHOOK_ERROR", err.message, req);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

// ==========================================
// F. KHỞI ĐỘNG HỆ THỐNG (STARTUP SEQUENCE)
// ==========================================
let pool; // Khai báo biến toàn cục nhưng chưa gán giá trị

async function bootstrap() {
    const secrets = await getSecretsFromVault();

    if (!secrets || !secrets.key || !secrets.webhookSecret) {
        console.error("❌ KHONG THE KHOI DONG: Thieu Encryption Key tu Vault!");
        process.exit(1); 
    }

    ENCRYPTION_KEY = secrets.key;
    process.env.WEBHOOK_SECRET = secrets.webhookSecret; // Đặt biến môi trường cho HMAC
    // 1. Cấu hình HTTPS (Đọc chứng chỉ mTLS)
    // Đảm bảo thư mục ./certs có đủ 3 file này
    const options = {
        key: fs.readFileSync('./certs/node.key'),
        cert: fs.readFileSync('./certs/node.crt'),
        ca: [fs.readFileSync('./certs/ca.crt')],
        requestCert: true,
        rejectUnauthorized: true
    };

    // 2. Khởi tạo Pool với DB URL từ Vault
    pool = new Pool({ 
        connectionString: secrets.dbUrl, 
        ssl: { rejectUnauthorized: false } 
    });

    // 3. Bật Server HTTPS
    https.createServer(options, app).listen(process.env.PORT || 3000, '0.0.0.0', () => {
        console.log('🔒 Order Service đã "sống" và lấy mọi thứ từ Vault!');
        console.log("🚀 Order Service da san sang voi Token tu Agent!");
    });
}

bootstrap();