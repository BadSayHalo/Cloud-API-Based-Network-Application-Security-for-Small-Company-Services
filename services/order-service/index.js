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

const logstashAgent = new https.Agent({
    ca: [ fs.readFileSync('./certs/ca-bundle.crt') ],
    rejectUnauthorized: true 
});

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
    ca: [ fs.readFileSync('./certs/ca-bundle.crt')],
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
        console.log("Dang doi Vault Agent cap Token...");
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
        console.error("[VAULT] Loi lay secret:", error.message);
        return { key: null, dbUrl: null, webhookSecret: null };
    }
}

// ==============================
// C. LOGGING, MÃ HÓA & XÁC THỰC
// ==============================
const getSafeKey = () => crypto.createHash('sha256').update(String(ENCRYPTION_KEY)).digest();

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
        await axios.post('https://logstash:5044', logData, { httpsAgent: logstashAgent });
    } catch (err) {}
}

function encrypt(text) {
    if (!text || !ENCRYPTION_KEY) return null;
    let iv = crypto.randomBytes(IV_LENGTH);
    let cipher = crypto.createCipheriv('aes-256-gcm', getSafeKey(), iv);
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
        let decipher = crypto.createDecipheriv('aes-256-gcm', getSafeKey(), iv, { authTagLength: 16 });
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

function hasRole(user, role) {
    return Boolean(user && Array.isArray(user.roles) && user.roles.includes(role));
}

function requireRole(role) {
    return function(req, res, next) {
        if (!hasRole(req.user, role)) {
            return res.status(403).json({ error: `Yeu cau quyen ${role}!` });
        }
        next();
    };
}

function requireAnyRole(allowedRoles) {
    return function(req, res, next) {
        if (!req.user || !Array.isArray(req.user.roles) || !allowedRoles.some(role => req.user.roles.includes(role))) {
            return res.status(403).json({ error: "Tai khoan khong co quyen thuc hien chuc nang nay!" });
        }
        next();
    };
}

let userColumnsCache = null;
async function getUserColumns() {
    if (userColumnsCache) return userColumnsCache;
    const { rows } = await pool.query(`
        SELECT column_name, data_type
        FROM information_schema.columns
        WHERE table_name = 'users'
    `);
    userColumnsCache = new Map(rows.map(row => [row.column_name, row.data_type]));
    return userColumnsCache;
}

async function ensureApplicationUser(user) {
    const columns = await getUserColumns();
    const has = name => columns.has(name);
    const idType = columns.get('id') || '';
    const username = user.username || user.email || user.keycloakId;
    const email = user.email || (String(username).includes('@') ? username : `${username}@keycloak.local`);
    const fullName = user.name || username;
    const role = hasRole(user, 'admin') ? 'admin' : (hasRole(user, 'customer') ? 'customer' : null);

    if (!role) {
        throw new Error("Token khong co role nghiep vu hop le");
    }

    const addField = (fields, values, name, value) => {
        if (has(name)) {
            fields.push(name);
            values.push(value);
        }
    };

    const lookupClauses = [];
    const lookupValues = [];
    if (has('username')) {
        lookupValues.push(username);
        lookupClauses.push(`username = $${lookupValues.length}`);
    }
    if (has('email')) {
        lookupValues.push(email);
        lookupClauses.push(`email = $${lookupValues.length}`);
    }
    if (idType.toLowerCase().includes('uuid')) {
        lookupValues.push(user.keycloakId);
        lookupClauses.push(`id = $${lookupValues.length}`);
    }
    if (lookupClauses.length > 0) {
        const existingByIdentity = await pool.query(
            `SELECT id FROM users WHERE ${lookupClauses.join(' OR ')} LIMIT 1`,
            lookupValues
        );
        if (existingByIdentity.rows.length > 0) return existingByIdentity.rows[0].id;
    }

    if (idType.toLowerCase().includes('uuid')) {
        const fields = [];
        const values = [];
        addField(fields, values, 'id', user.keycloakId);
        addField(fields, values, 'username', username);
        addField(fields, values, 'email', email);
        addField(fields, values, 'full_name', fullName);
        addField(fields, values, 'password_hash', 'KEYCLOAK_MANAGED');
        addField(fields, values, 'role', role);
        addField(fields, values, 'is_active', true);

        const placeholders = fields.map((_, index) => `$${index + 1}`).join(', ');
        const updates = fields
            .filter(field => field !== 'id' && field !== 'password_hash')
            .map(field => `${field} = EXCLUDED.${field}`)
            .join(', ');
        const conflictAction = updates ? `DO UPDATE SET ${updates}` : 'DO NOTHING';
        const query = `
            INSERT INTO users (${fields.join(', ')})
            VALUES (${placeholders})
            ON CONFLICT (id) ${conflictAction}
            RETURNING id
        `;
        const { rows } = await pool.query(query, values);
        return rows[0]?.id || user.keycloakId;
    }

    const fields = [];
    const values = [];
    addField(fields, values, 'username', username);
    addField(fields, values, 'email', email);
    addField(fields, values, 'full_name', fullName);
    addField(fields, values, 'password_hash', 'KEYCLOAK_MANAGED');
    addField(fields, values, 'role', role);
    addField(fields, values, 'is_active', true);
    const placeholders = fields.map((_, index) => `$${index + 1}`).join(', ');
    const { rows } = await pool.query(
        `INSERT INTO users (${fields.join(', ')}) VALUES (${placeholders}) RETURNING id`,
        values
    );
    return rows[0].id;
}

function verifyUserContext(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ error: "Missing Token" });
    const token = authHeader.split(' ')[1];
    jwt.verify(token, getKey, { algorithms: ['ES256'] }, async function(err, decoded) {
        if (err) return res.status(401).json({ error: "Invalid or Expired Token" });
        try {
            req.user = {
                id: decoded.sub,
                keycloakId: decoded.sub,
                username: decoded.preferred_username || decoded.email || 'unknown',
                email: decoded.email,
                name: decoded.name,
                roles: decoded.realm_access?.roles || []
            };
            req.user.id = await ensureApplicationUser(req.user);
            next();
        } catch (syncErr) {
            console.error("[AUTH] Khong the dong bo user tu Keycloak vao DB:", syncErr.message);
            res.status(500).json({ error: "Khong the dong bo tai khoan nguoi dung voi database" });
        }
    });
}

function verifyHMACSignature(req, res, next) {
    const signature = req.headers['x-webhook-signature'];
    const timestamp = req.headers['x-webhook-timestamp'];
    const secret = process.env.WEBHOOK_SECRET;

    if (!secret) return res.status(500).json({ error: "Webhook Secret is missing!" });

    const now = Math.floor(Date.now() / 1000);
    if (!timestamp || Math.abs(now - timestamp) > 300) {
        sendLog("CRITICAL", "REPLAY_ATTACK_ATTEMPT", `Phát hiện Webhook quá hạn hoặc không có Timestamp từ IP: ${req.headers['x-forwarded-for'] || req.socket.remoteAddress}`, req);
        return res.status(401).json({ error: "Request expired" });
    }
    
    const rawBodyString = req.rawBody ? req.rawBody.toString('utf8') : '';
    const hmac = crypto.createHmac('sha256', secret).update(timestamp + rawBodyString).digest('hex');

    if (signature && crypto.timingSafeEqual(Buffer.from(hmac), Buffer.from(signature))) {
        next();
    } else {
        sendLog("CRITICAL", "INVALID_HMAC_SIGNATURE", `Phát hiện HMAC Signature không hợp lệ từ IP: ${req.headers['x-forwarded-for'] || req.socket.remoteAddress}`, req);
        res.status(401).json({ error: "Invalid HMAC Signature!" });
    }
}

// ==========================================
// THREAT DETECTION MIDDLEWARE (WAF MỀM)
// ==========================================
function securityMonitor(req, res, next) {
    const payloadString = JSON.stringify(req.body || {}).toLowerCase();
    
    // 1. Phát hiện SQL Injection (SQLi) & Cross-Site Scripting (XSS) cơ bản
    const sqlXssPattern = /(\b(select|update|delete|insert|drop|alter)\b)|(<script>|javascript:|onerror=)/i;
    if (sqlXssPattern.test(payloadString)) {
        sendLog("CRITICAL", "SQLI_XSS_ATTACK_ATTEMPT", `Phát hiện payload độc hại từ IP: ${req.headers['x-forwarded-for'] || req.socket.remoteAddress}. Payload: ${payloadString}`, req);
        return res.status(403).json({ error: "Phát hiện hành vi đáng ngờ. Request bị từ chối!" });
    }

    // 2. Phát hiện Leo thang đặc quyền (Privilege Escalation / Mass Assignment)
    if (req.body.role || req.body.is_admin || req.body.permissions) {
        sendLog("CRITICAL", "PRIVILEGE_ESCALATION_ATTEMPT", `User cố gắng chèn trường phân quyền vào body!`, req);
        return res.status(403).json({ error: "Trường dữ liệu không được phép!" });
    }

    next();
}

// ==========================================
// D. API ROUTES 
// ==========================================
app.post('/api/v1/orders', verifyUserContext, requireAnyRole(['customer', 'admin']), async (req, res) => {
    try {
        // CHÚ Ý: Cố tình KHÔNG LẤY unit_price và item_name từ req.body nữa!
        const { sku, qty, customer_phone } = req.body;
        
        // BẢO MẬT 2: Data Validation 
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
        
        //BẢO MẬT GIAO TIẾP (East-West Traffic): Lấy giá chuẩn từ Product Service
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
    } catch (err) {
        sendLog("ERROR", "SYSTEM_ERROR", err.message, req);
        res.status(500).json({ error: "Lỗi hệ thống: " + err.message });
    }
});

app.get('/api/v1/orders', verifyUserContext, requireAnyRole(['customer', 'admin']), async (req, res) => {
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
    } catch (err) { 
        sendLog("ERROR", "SYSTEM_ERROR", err.message, req);
        res.status(500).json({ error: "Internal Error" }); 
    }
});

// User tự hủy đơn hàng của chính mình
app.patch('/api/v1/orders/:orderId/cancel', verifyUserContext, requireAnyRole(['customer', 'admin']), async (req, res) => {
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
        
        res.json({ message: `Đã hủy thành công đơn hàng #${req.params.orderId} và hoàn kho.` });
    } catch (err) {
        sendLog("ERROR", "SYSTEM_ERROR", err.message, req);
        res.status(500).json({ error: "Lỗi hệ thống: " + err.message });
    }
});

// User xác nhận đã nhận hàng
app.patch('/api/v1/orders/:orderId/deliver', verifyUserContext, requireAnyRole(['customer', 'admin']), async (req, res) => {
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
        
        res.json({ message: `Cảm ơn bạn! Đơn hàng #${req.params.orderId} đã được giao thành công.` });
    } catch (err) {
        sendLog("ERROR", "SYSTEM_ERROR", err.message, req);
        res.status(500).json({ error: "Lỗi hệ thống: " + err.message });
    }
});

app.post('/api/v1/profile', verifyUserContext, requireAnyRole(['customer', 'admin']), async (req, res) => {
    try {
        const { phone, city } = req.body;
        
        // 1. Kiểm tra đầu vào
        if (!phone || !city) {
            return res.status(400).json({ error: "Vui lòng điền đủ Số điện thoại và Thành phố!" });
        }

        if (phone?.length > 20 || city?.length > 100) {
            sendLog("CRITICAL", "BUFFER_OVERFLOW_ATTEMPT", `Data đầu vào quá dài: phone(${phone?.length}), city(${city?.length})`, req);
            return res.status(400).json({ error: "Độ dài dữ liệu không hợp lệ!" });
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
        res.status(200).json({ message: "Đã lưu và mã hóa thông tin hồ sơ an toàn!" });
    } catch (err) {
        sendLog("ERROR", "SYSTEM_ERROR", err.message, req);
        res.status(500).json({ error: "Lỗi hệ thống: " + err.message });
    }
});

// 3. ADMIN: Lấy danh sách Users (Nối đúng kiểu UUID)
app.get('/api/v1/admin/users', verifyUserContext, requireRole('admin'), async (req, res) => {
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
app.get('/api/v1/admin/orders/:userId', verifyUserContext, requireRole('admin'), async (req, res) => {
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
app.patch('/api/v1/admin/orders/:orderId/payment', verifyUserContext, requireRole('admin'), async (req, res) => {
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
        let rawOrderId = req.body.order_id || req.body.orderId;
        if (rawOrderId && typeof rawOrderId === 'object') {
            rawOrderId = rawOrderId.order_id || rawOrderId.orderId || rawOrderId.id;
        }

        const order_id = Number(rawOrderId);
        if (!Number.isInteger(order_id) || order_id <= 0) {
            sendLog("WARN", "INVALID_WEBHOOK_ORDER_ID", `Webhook order_id khong hop le: ${JSON.stringify(req.body)}`, req);
            return res.status(400).json({ error: "Invalid order_id" });
        }
        
        // Cập nhật trạng thái đơn hàng thành Paid
        const checkQuery = 'SELECT status, payment_status FROM orders WHERE id = $1';
        const { rows } = await pool.query(checkQuery, [order_id]);
        
        if (rows.length === 0) {
            sendLog("WARN", "PAYMENT_FUZZING_ATTEMPT", `Webhook báo thanh toán cho đơn hàng không tồn tại: ${order_id}`, req);
            return res.status(404).json({ error: "Order not found" });
        }
        
        if (rows[0].payment_status === 'Paid') {
            sendLog("WARN", "DUPLICATE_PAYMENT_ATTEMPT", `Đơn hàng ${order_id} đã được thanh toán trước đó, cẩn thận tấn công Double Spend!`, req);
            return res.status(200).json({ message: "Đã xử lý trước đó" }); 
        }

        await pool.query("UPDATE orders SET payment_status = 'Paid', status = 'Processing' WHERE id = $1", [order_id]);

        res.status(200).json({ message: "Webhook processed successfully" });
    } catch (err) {
        sendLog("ERROR", "WEBHOOK_ERROR", err.message, req);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

// ==========================================
// E. KHỞI ĐỘNG HỆ THỐNG (ORDER SERVICE)
// ==========================================
async function bootstrap() {
    try {
        // 1. Chờ lấy Token từ Vault Agent
        const VAULT_TOKEN = await getVaultToken();
        
        // 2. Lấy TOÀN BỘ Secrets (DB URL, Key, Webhook) từ Vault
        const secrets = await getSecretsFromVault(VAULT_TOKEN);
        if (!secrets.dbUrl || !secrets.key) {
            console.error("KHÔNG THỂ KHỞI ĐỘNG: Thiếu DB URL hoặc Encryption Key từ Vault!");
            process.exit(1); 
        }
        
        // Cấp phát Key cho toàn cục
        ENCRYPTION_KEY = secrets.key;
        process.env.WEBHOOK_SECRET = secrets.webhookSecret;

        // 3. Đứng chờ Vault Agent sinh file chứng chỉ ra ổ cứng
        const bundlePath = './certs/order-bundle.json';
        
        while (!fs.existsSync(bundlePath)) {
            console.log("Đang chờ Vault Agent cấp chứng chỉ (order-bundle.json)...");
            await new Promise(res => setTimeout(res, 2000));
        }

        // 4. Đọc chứng chỉ từ file JSON
        const bundleData = JSON.parse(fs.readFileSync(bundlePath, 'utf8'));
        const orderCert = bundleData.certificate;
        const orderKey = bundleData.private_key;
        const dynamicCa = bundleData.issuing_ca;

        // 5. Cấu hình Internal Agent
        internalHttpsAgent = new https.Agent({
            key: orderKey,
            cert: orderCert,
            // Nạp cả Root CA, Int CA và CA động từ Vault vào
            ca: [ fs.readFileSync('./certs/ca-bundle.crt'), dynamicCa ],
            rejectUnauthorized: true 
        });

        // 6. Cấu hình HTTPS Server
        const options = {
            key: orderKey,
            cert: orderCert,
            ca: [ fs.readFileSync('./certs/ca-bundle.crt')],
            requestCert: true,
            rejectUnauthorized: true
        };

        // 7. Kết nối DB Order
        pool = new Pool({ 
            connectionString: secrets.dbUrl, 
            ssl: { 
                rejectUnauthorized: true,    
                ca: fs.readFileSync('./certs/neon-root-ca.pem').toString() 
            }
        });

        // 8. Bật Server (Order Service chạy cổng 3000)
        const PORT = process.env.PORT || 3000;
        https.createServer(options, app).listen(PORT, '0.0.0.0', () => {
            console.log('============================================');
            console.log(`Order Service đã khởi động (Cổng ${PORT})`);
            console.log('Đã nạp Encryption Key & Webhook Secret.');
            console.log('============================================');
        });

    } catch (err) {
        console.error("Fatal Error:", err);
        process.exit(1);
    }
}

bootstrap();
