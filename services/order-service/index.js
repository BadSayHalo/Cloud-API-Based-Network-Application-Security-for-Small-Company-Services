const express = require('express');
const { Pool } = require('pg');
const https = require('https');
const fs = require('fs');
const crypto = require('crypto');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const app = express();
app.use(express.json({
    limit: '5mb', 
    verify: (req, res, buf) => {
        req.rawBody = buf; 
    }
})); 

// ==========================================
// A. CẤU HÌNH BIẾN TOÀN CỤC & HTTPS AGENT CHO VAULT
// ==========================================
const VAULT_ADDR = process.env.VAULT_ADDR || 'https://vault-server:8200'; // Đổi thành HTTPS
let ENCRYPTION_KEY = ""; 
const IV_LENGTH = 16;
let pool; 
let internalHttpsAgent; // Sẽ khởi tạo sau khi có chứng chỉ động

// Agent chuyên dụng để Node.js gọi vào Vault (Vì Vault đang xài mTLS tĩnh)
const vaultHttpsAgent = new https.Agent({
    ca: fs.readFileSync('./certs/ca.crt'), // Root CA để tin tưởng Vault Server
    checkServerIdentity: () => undefined 
});

// ==========================================
// B. CÁC HÀM GIAO TIẾP VỚI VAULT (SECRETS & PKI)
// ==========================================
async function getVaultToken() {
    const tokenPath = '/app/vault-token-share/.vault-token';
    for (let i = 0; i < 10; i++) {
        if (fs.existsSync(tokenPath)) {
            return fs.readFileSync(tokenPath, 'utf8').trim();
        }
        console.log("⏳ Dang doi Vault Agent cap Token...");
        await new Promise(res => setTimeout(res, 1000));
    }
    throw new Error("Timeout: Khong nhan duoc Token tu Vault Agent!");
}

async function getSecretsFromVault(token) {
    try {
        const response = await axios.get(`${VAULT_ADDR}/v1/secret/data/order-service`, {
            headers: { 'X-Vault-Token': token },
            httpsAgent: vaultHttpsAgent
        });
        const vaultData = response.data.data.data;
        return {
            key: vaultData.ENCRYPTION_KEY, 
            dbUrl: vaultData.DATABASE_URL,
            webhookSecret: vaultData.WEBHOOK_SECRET
        };
    } catch (error) {
        console.error("❌ [VAULT] Loi lay secret:", error.message);
        return { key: null, dbUrl: null, webhookSecret: null };
    }
}

async function getDynamicCertFromVault(token) {
    try {
        console.log("🔐 Dang xin cap chung chi mTLS (ECC) tu Vault RA...");
        const response = await axios.post(`${VAULT_ADDR}/v1/pki/issue/microservices`, {
            common_name: "backend-order-api",
            alt_names: "localhost",
            ip_sans: "127.0.0.1",
            ttl: "24h"
        }, {
            headers: { 'X-Vault-Token': token },
            httpsAgent: vaultHttpsAgent
        });
        
        return {
            cert: response.data.data.certificate,
            key: response.data.data.private_key,
            dynamic_ca: response.data.data.issuing_ca
        };
    } catch (error) {
        console.error("❌ [VAULT PKI] Loi xin chung chi:", error.message);
        throw error;
    }
}

// ==========================================
// C. LOGGING, MÃ HÓA & XÁC THỰC (Giữ nguyên logic của bạn)
// ==========================================
async function sendLog(level, action, message, req = null) {
    const logData = {
        timestamp: new Date().toISOString(),
        service: "order-service",
        level: level,       
        action: action,     
        message: message,
        user_id: req && req.user ? req.user.id : "anonymous",
        ip_address: req ? (req.headers['x-forwarded-for'] || req.socket.remoteAddress) : "N/A"
    };
    try {
        await axios.post('http://logstash:5044', logData);
    } catch (err) {}
}

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

const client = jwksClient({
  jwksUri: 'http://keycloak-idp:8080/realms/laptop-store/protocol/openid-connect/certs' 
});

function getKey(header, callback) {
  client.getSigningKey(header.kid, function(err, key) {
    var signingKey = key.publicKey || key.rsaPublicKey;
    callback(null, signingKey);
  });
}

function verifyUserContext(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ error: "Missing Token" });
    const token = authHeader.split(' ')[1];
    jwt.verify(token, getKey, { algorithms: ['ES256'] }, function(err, decoded) {
        if (err) return res.status(401).json({ error: "Invalid or Expired Token" });
        req.user = { 
            id: decoded.sub, 
            username: decoded.preferred_username || 'unknown', 
            roles: decoded.realm_access?.roles || [] 
        };
        next();
    });
}

function verifyHMACSignature(req, res, next) {
    const signature = req.headers['x-webhook-signature'];
    const timestamp = req.headers['x-webhook-timestamp'];
    const secret = process.env.WEBHOOK_SECRET;

    if (!secret) return res.status(500).json({ error: "Webhook Secret is missing!" });

    const now = Math.floor(Date.now() / 1000);
    if (!timestamp || Math.abs(now - timestamp) > 300) {
        return res.status(401).json({ error: "Request expired" });
    }

    const rawBodyString = req.rawBody ? req.rawBody.toString('utf8') : '';
    const hmac = crypto.createHmac('sha256', secret).update(timestamp + rawBodyString).digest('hex');

    if (signature && crypto.timingSafeEqual(Buffer.from(hmac), Buffer.from(signature))) {
        next();
    } else {
        res.status(401).json({ error: "Invalid HMAC Signature!" });
    }
}

// ==========================================
// D. API ROUTES 
// ==========================================
app.post('/api/v1/orders', verifyUserContext, async (req, res) => {
    try {
        // CHÚ Ý: Cố tình KHÔNG LẤY unit_price và item_name từ req.body nữa!
        const { sku, qty, customer_phone } = req.body;
        
        // 🛡️ BẢO MẬT 2: Data Validation 
        if (!sku) {
            return res.status(400).json({ error: "Thiếu mã sản phẩm (SKU)!" });
        }

        const qtyNum = Number(qty);

        if (!Number.isInteger(qtyNum)) {
            sendLog("WARN", "INVALID_INPUT", `User ${req.user.id} truyền số lượng không phải số nguyên: ${qty}`, req);
            return res.status(400).json({ error: "Số lượng mua phải là một số nguyên!" });
        }

        if (qtyNum <= 0) {
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
// E. KHỞI ĐỘNG HỆ THỐNG (BỘ NÃO ZERO-TRUST)
// ==========================================
async function bootstrap() {
    try {
        // 1. Chờ lấy Token từ Thư ký Agent
        const VAULT_TOKEN = await getVaultToken();

        // 2. Lấy DB URL & Secret Key
        const secrets = await getSecretsFromVault(VAULT_TOKEN);
        if (!secrets.key) {
            console.error("❌ KHONG THE KHOI DONG: Thieu Encryption Key tu Vault!");
            process.exit(1); 
        }
        ENCRYPTION_KEY = secrets.key;
        process.env.WEBHOOK_SECRET = secrets.webhookSecret;

        // 3. Lấy Chứng chỉ mTLS động từ Vault PKI
        const certs = await getDynamicCertFromVault(VAULT_TOKEN);

        // 4. Cấu hình Agent nội bộ (Dùng để Order gọi sang Product)
        internalHttpsAgent = new https.Agent({
            key: certs.key,         // Private Key động
            cert: certs.cert,       // Chứng chỉ động
            ca: [certs.dynamic_ca], // Trust CA động của Vault
            checkServerIdentity: () => undefined, 
            rejectUnauthorized: true 
        });

        // 5. Cấu hình HTTPS Server (Dùng để Kong gọi vào Order)
        const options = {
            key: certs.key,
            cert: certs.cert,
            // ĐIỂM SÁNG KIẾN TRÚC: Nạp cả CÂY NIỀM TIN
            ca: [
                fs.readFileSync('./certs/ca.crt'),      // Chấp nhận Root CA
                fs.readFileSync('./certs/int-ca.crt'),  // Chấp nhận Kong (Vì Kong xài cert tĩnh)
                certs.dynamic_ca                        // Chấp nhận các Service khác (Xài cert động)
            ],
            requestCert: true,
            rejectUnauthorized: true
        };

        // 6. Kết nối Database
        pool = new Pool({ 
            connectionString: secrets.dbUrl, 
            ssl: { 
                rejectUnauthorized: true,    
                ca: fs.readFileSync('./certs/neon-root-ca.pem').toString() 
            }
        });

        // 7. Mở cổng
        https.createServer(options, app).listen(process.env.PORT || 3000, '0.0.0.0', () => {
            console.log('============================================');
            console.log('🔒 Order Service đã khởi động (Pure ECC)!');
            console.log('🔑 Đã nạp Encryption Key & Webhook Secret.');
            console.log('📜 Đã lấy chứng chỉ mTLS động từ Vault.');
            console.log('🛡️ Server đang lắng nghe mTLS trên cổng 3000.');
            console.log('============================================');
        });

    } catch (err) {
        console.error("❌ Fatal Error trong qua trinh Boot:", err);
        process.exit(1);
    }
}

bootstrap();