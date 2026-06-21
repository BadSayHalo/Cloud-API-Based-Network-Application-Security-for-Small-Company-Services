const express = require('express');
const { Pool } = require('pg');
const https = require('https');
const fs = require('fs');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const app = express();
// BẢO MẬT: Giới hạn dung lượng payload để chống DDoS tràn bộ nhớ
app.use(express.json({
    limit: '5mb', 
    verify: (req, res, buf) => {
        req.rawBody = buf; 
    }
}));

// ==========================================
// A. CẤU HÌNH VAULT & BIẾN TOÀN CỤC
// ==========================================
const VAULT_ADDR = process.env.VAULT_ADDR || 'https://vault-server:8200';
let pool; 
let internalHttpsAgent;

// Agent chuyên dụng cho Vault
const vaultHttpsAgent = new https.Agent({
    ca: [ fs.readFileSync('./certs/ca-bundle.crt') ], 
});

// Agent chuyên dụng để bắn log sang ELK
const logstashAgent = new https.Agent({
    ca: [ fs.readFileSync('./certs/ca-bundle.crt') ],
    rejectUnauthorized: true 
});

// ==========================================
// B. HỆ THỐNG GIÁM SÁT & BÁO CÁO (SIEM)
// ==========================================
async function sendLog(level, action, message, req = null) {
    const logData = {
        timestamp: new Date().toISOString(),
        service: "product-service", // Đã đổi tên để phân biệt với order-service
        level: level,       
        action: action,     
        message: message,
        user_id: req && req.user ? req.user.id : "anonymous",
        ip_address: req ? (req.headers['x-forwarded-for'] || req.socket.remoteAddress) : "N/A"
    };
    try {
        await axios.post('https://logstash:5044', logData, {
            httpsAgent: logstashAgent,
            timeout: 3000
        });
    } catch (err) {}
}

const KEYCLOAK_BASE_URL = process.env.KEYCLOAK_BASE_URL || 'http://keycloak-idp:8080';
const client = jwksClient({
  jwksUri: `${KEYCLOAK_BASE_URL}/realms/laptop-store/protocol/openid-connect/certs`,
  cache: true,
  cacheMaxEntries: 5,
  cacheMaxAge: 10 * 60 * 1000,
  timeout: 5000
});

function getKey(header, callback) {
  if (!header || !header.kid) {
    return callback(new Error('Missing JWT kid'));
  }

  client.getSigningKey(header.kid, function(err, key) {
    if (err) {
      console.error('[JWT] Khong lay duoc signing key:', err.message, 'kid=', header.kid);
      return callback(err);
    }

    if (!key) {
      return callback(new Error('Signing key not found'));
    }

    const signingKey = key.getPublicKey ? key.getPublicKey() : (key.publicKey || key.rsaPublicKey);
    if (!signingKey) {
      return callback(new Error('Signing key has no public key material'));
    }

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

// ==========================================
// THREAT DETECTION MIDDLEWARE (WAF MỀM)
// ==========================================
function securityMonitor(req, res, next) {
    const payloadString = JSON.stringify(req.body || {}).toLowerCase();
    
    // 1. Phát hiện SQL Injection (SQLi) & Cross-Site Scripting (XSS)
    const sqlXssPattern = /(\b(select|update|delete|insert|drop|alter)\b)|(<script>|javascript:|onerror=)/i;
    if (sqlXssPattern.test(payloadString)) {
        sendLog("CRITICAL", "SQLI_XSS_ATTACK_ATTEMPT", `Phát hiện payload độc hại. Payload: ${payloadString}`, req);
        return res.status(403).json({ error: "Phát hiện hành vi đáng ngờ. Request bị từ chối!" });
    }

    // 2. Phát hiện cố tình truyền data quá lớn (Parameter Tampering)
    if (payloadString.length > 5000) {
        sendLog("WARN", "LARGE_PAYLOAD_ATTEMPT", `Data đầu vào quá lớn bất thường!`, req);
    }

    next();
}

// Middleware Chốt chặn siêu cấp bảo mật mTLS (Có thêm Alert)
function requireInternalMTLS(req, res, next) {
    const cert = req.socket.getPeerCertificate();
    
    // 1. Nếu không có chứng chỉ hoặc chứng chỉ không do CA nội bộ cấp
    if (!req.client.authorized || !cert || !cert.subject) {
        sendLog("CRITICAL", "UNAUTHORIZED_MTLS_ACCESS", `IP ${req.socket.remoteAddress} cố gắng gọi API nội bộ mà không có chứng chỉ mTLS!`, req);
        return res.status(403).json({ error: "Forbidden: Yêu cầu chứng chỉ mTLS hợp lệ!" });
    }

    // 2. [BẢO MẬT CHIỀU SÂU]: Chỉ đích danh 'backend-order-api' mới được phép trừ/hoàn kho
    if (cert.subject.CN !== 'backend-order-api') {
        sendLog("CRITICAL", "UNAUTHORIZED_SERVICE_ACCESS", `Service lạ (${cert.subject.CN}) định can thiệp kho hàng!`, req);
        return res.status(403).json({ error: "Forbidden: Bạn không có quyền can thiệp kho hàng!" });
    }

    next();
}

// ==========================================
// C. CÁC HÀM GIAO TIẾP VỚI VAULT
// ==========================================
async function getVaultToken() {
    const tokenPath = '/app/vault-token-share/.vault-token';
    for (let i = 0; i < 10; i++) {
        if (fs.existsSync(tokenPath)) {
            return fs.readFileSync(tokenPath, 'utf8').trim();
        }
        console.log("Dang doi Vault Agent cap Token cho Product Service...");
        await new Promise(res => setTimeout(res, 1000));
    }
    throw new Error("Timeout: Khong nhan duoc Token tu Vault Agent!");
}

async function getDbUrlFromVault(token) {
    try {
        // LƯU Ý: Đang dùng chung secret/data/order-service của Order Service để lấy DB_URL. 
        // Nếu sau này bạn tách DB, nhớ đổi đường dẫn này thành secret/data/product-service
        const response = await axios.get(`${VAULT_ADDR}/v1/secret/data/order-service`, {
            headers: { 'X-Vault-Token': token },
            httpsAgent: vaultHttpsAgent
        });
        return response.data.data.data.DATABASE_URL;
    } catch (error) {
        console.error("[VAULT] Loi lay DB URL:", error.message);
        return null;
    }
}

// ==========================================
// D. API ROUTES
// ==========================================

// 1. API cho Khách xem danh sách
app.get('/api/v1/products', securityMonitor, async (req, res) => {
    try {
        const { rows } = await pool.query('SELECT sku, name, price, stock, brand_id, category_id FROM products ORDER BY name ASC');
        res.status(200).json({ 
            message: "Lấy danh sách sản phẩm thành công",
            total: rows.length,
            data: rows 
        });
    } catch (err) {
        sendLog("ERROR", "SYSTEM_ERROR", err.message, req);
        res.status(500).json({ error: "Lỗi kết nối CSDL Sản phẩm" });
    }
});

// 2. API cho Order Service check giá
app.get('/api/v1/products/:sku', securityMonitor, async (req, res) => {
    try {
        const sku = req.params.sku;
        const { rows } = await pool.query('SELECT * FROM products WHERE sku = $1', [sku]);
        if (rows.length === 0) return res.status(404).json({ error: `Không tìm thấy SKU: ${sku}` });
        res.status(200).json({ data: rows[0] });
    } catch (err) {
        sendLog("ERROR", "SYSTEM_ERROR", err.message, req);
        res.status(500).json({ error: "Lỗi hệ thống khi tra cứu SKU" });
    }
});

// 2.1 API Admin xem tồn kho sản phẩm
app.get('/api/v1/admin/products', verifyUserContext, requireRole('admin'), securityMonitor, async (req, res) => {
    try {
        const { rows } = await pool.query('SELECT sku, name, stock FROM products ORDER BY name ASC');
        res.status(200).json({
            message: "Lấy danh sách tồn kho thành công",
            total: rows.length,
            data: rows
        });
    } catch (err) {
        sendLog("ERROR", "SYSTEM_ERROR", err.message, req);
        res.status(500).json({ error: "Lỗi kết nối CSDL Sản phẩm" });
    }
});

// 2.2 API Admin điều chỉnh tồn kho
app.patch('/api/v1/admin/products/:sku/stock', verifyUserContext, requireRole('admin'), securityMonitor, async (req, res) => {
    const { sku } = req.params;
    const { action, quantity } = req.body;
    const qty = Number(quantity);

    if (!Number.isInteger(qty) || qty <= 0) {
        return res.status(400).json({ error: "quantity phải là số nguyên dương" });
    }
    if (action !== 'increase' && action !== 'decrease') {
        return res.status(400).json({ error: "action phải là increase hoặc decrease" });
    }

    try {
        let query;
        let params;

        if (action === 'increase') {
            query = 'UPDATE products SET stock = stock + $1 WHERE sku = $2 RETURNING sku, name, stock';
            params = [qty, sku];
        } else {
            query = 'UPDATE products SET stock = stock - $1 WHERE sku = $2 AND stock >= $1 RETURNING sku, name, stock';
            params = [qty, sku];
        }

        const { rows } = await pool.query(query, params);

        if (rows.length === 0) {
            if (action === 'decrease') {
                return res.status(409).json({ error: "Không đủ tồn kho để giảm theo số lượng yêu cầu" });
            }
            return res.status(404).json({ error: `Không tìm thấy SKU: ${sku}` });
        }

        res.status(200).json({
            message: `Cập nhật tồn kho thành công (${action})`,
            data: rows[0]
        });
    } catch (err) {
        sendLog("ERROR", "SYSTEM_ERROR", err.message, req);
        res.status(500).json({ error: "Lỗi DB khi cập nhật tồn kho" });
    }
});

// 3. API Trừ số lượng (Có bảo vệ mTLS kép)
app.patch('/api/v1/products/:sku/reduce-stock', requireInternalMTLS, securityMonitor, async (req, res) => {
    const { qty } = req.body;
    const { sku } = req.params;
    try {
        const query = `UPDATE products SET stock = stock - $1 WHERE sku = $2 AND stock >= $1 RETURNING *`;
        const { rows } = await pool.query(query, [qty, sku]);
        
        if (rows.length === 0) {
            sendLog("WARN", "STOCK_REDUCTION_FAILED", `Không đủ hàng trong kho cho SKU: ${sku}, yêu cầu trừ: ${qty}`, req);
            return res.status(400).json({ error: "Hết hàng hoặc số lượng tồn kho không đủ!" });
        }
        
        res.status(200).json({ message: "Trừ kho thành công", product: rows[0] });
    } catch (err) { 
        sendLog("ERROR", "SYSTEM_ERROR", err.message, req);
        res.status(500).json({ error: "Lỗi DB khi cập nhật kho" }); 
    }
});

// 4. API Hoàn số lượng (Có bảo vệ mTLS kép)
app.patch('/api/v1/products/:sku/add-stock', requireInternalMTLS, securityMonitor, async (req, res) => {
    const { qty } = req.body;
    const { sku } = req.params;
    try {
        const query = `UPDATE products SET stock = stock + $1 WHERE sku = $2 RETURNING *`;
        const { rows } = await pool.query(query, [qty, sku]);
        
        if (rows.length === 0) return res.status(404).json({ error: "Không tìm thấy sản phẩm để hoàn kho!" });
        res.status(200).json({ message: "Hoàn kho thành công", product: rows[0] });
    } catch (err) { 
        sendLog("ERROR", "SYSTEM_ERROR", err.message, req);
        res.status(500).json({ error: "Lỗi DB khi hoàn kho" }); 
    }
});

// ==========================================
// E. KHỞI ĐỘNG HỆ THỐNG CÙNG mTLS
// ==========================================
async function bootstrap() {
    try {
        // 1. Chờ lấy Token từ Vault Agent
        const VAULT_TOKEN = await getVaultToken();
        
        // 2. Lấy DB URL từ Vault
        const dbUrl = await getDbUrlFromVault(VAULT_TOKEN);
        if (!dbUrl) {
            console.error("KHÔNG THỂ KHỞI ĐỘNG: Không lấy được DB URL từ Vault!");
            process.exit(1); 
        }

        // 3. Đứng chờ Vault Agent sinh file chứng chỉ ra ổ cứng
        const bundlePath = './certs/product-bundle.json'; 
        
        while (!fs.existsSync(bundlePath)) {
            console.log("Đang chờ Vault Agent cấp chứng chỉ (product-bundle.json)...");
            await new Promise(res => setTimeout(res, 2000));
        }

        // 4. Đọc chứng chỉ từ file JSON
        const bundleData = JSON.parse(fs.readFileSync(bundlePath, 'utf8'));
        const productCert = bundleData.certificate;
        const productKey = bundleData.private_key;
        const dynamicCa = bundleData.issuing_ca;

        // 5. Cấu hình HTTPS Server
        const options = {
            key: productKey,
            cert: productCert,
            ca: [ fs.readFileSync('./certs/ca-bundle.crt') ],
            requestCert: true,
            rejectUnauthorized: true
        };

        // 6. Kết nối DB
        pool = new Pool({ 
            connectionString: dbUrl, 
            ssl: { 
                rejectUnauthorized: true,    
                ca: fs.readFileSync('./certs/neon-root-ca.pem').toString() 
            }
        });

        // 7. Bật Server (Cổng 3001)
        const PORT = process.env.PORT || 3001;
        https.createServer(options, app).listen(PORT, '0.0.0.0', () => {
            console.log('============================================');
            console.log(`Product Service đã khởi động (Cổng ${PORT})`);
            console.log('============================================');
        });

    } catch (err) {
        console.error("Fatal Error:", err);
        process.exit(1);
    }
}

bootstrap();
