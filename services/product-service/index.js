const express = require('express');
const { Pool } = require('pg');
const https = require('https');
const fs = require('fs');
const axios = require('axios');

const app = express();
app.use(express.json());

// ==========================================
// A. CẤU HÌNH VAULT & BIẾN TOÀN CỤC
// ==========================================
// BẮT BUỘC dùng HTTPS để giao tiếp với Vault Server mới
const VAULT_ADDR = process.env.VAULT_ADDR || 'https://vault-server:8200';
let pool; 

// Agent chuyên dụng để Product Service gọi vào Vault an toàn
const vaultHttpsAgent = new https.Agent({
    ca: fs.readFileSync('./certs/ca.crt'), 
    checkServerIdentity: () => undefined 
});

// ==========================================
// B. CÁC HÀM GIAO TIẾP VỚI VAULT
// ==========================================
async function getVaultToken() {
    const tokenPath = '/app/vault-token-share/.vault-token';
    for (let i = 0; i < 10; i++) {
        if (fs.existsSync(tokenPath)) {
            return fs.readFileSync(tokenPath, 'utf8').trim();
        }
        console.log("⏳ Dang doi Vault Agent cap Token cho Product Service...");
        await new Promise(res => setTimeout(res, 1000));
    }
    throw new Error("Timeout: Khong nhan duoc Token tu Vault Agent!");
}

async function getDbUrlFromVault(token) {
    try {
        const response = await axios.get(`${VAULT_ADDR}/v1/secret/data/order-service`, {
            headers: { 'X-Vault-Token': token },
            httpsAgent: vaultHttpsAgent
        });
        return response.data.data.data.DATABASE_URL;
    } catch (error) {
        console.error("❌ [VAULT] Loi lay DB URL:", error.message);
        return null;
    }
}

async function getDynamicCertFromVault(token) {
    try {
        console.log("🔐 Dang xin cap chung chi mTLS (ECC) tu Vault RA...");
        const response = await axios.post(`${VAULT_ADDR}/v1/pki/issue/microservices`, {
            common_name: "backend-product-api", // Tên định danh của Product Service
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
// C. API ROUTES
// ==========================================

// 1. API cho Khách xem danh sách (Mở cho Kong Gateway truy cập)
app.get('/api/v1/products', async (req, res) => {
    try {
        const { rows } = await pool.query('SELECT sku, name, price, stock, brand_id, category_id FROM products ORDER BY name ASC');
        res.status(200).json({ 
            message: "Lấy danh sách sản phẩm thành công",
            total: rows.length,
            data: rows 
        });
    } catch (err) {
        console.error("Lỗi lấy danh sách sản phẩm:", err.message);
        res.status(500).json({ error: "Lỗi kết nối CSDL Sản phẩm" });
    }
});

// 2. API cho Order Service check giá
app.get('/api/v1/products/:sku', async (req, res) => {
    try {
        const sku = req.params.sku;
        const { rows } = await pool.query('SELECT * FROM products WHERE sku = $1', [sku]);
        if (rows.length === 0) return res.status(404).json({ error: `Không tìm thấy SKU: ${sku}` });
        res.status(200).json({ data: rows[0] });
    } catch (err) {
        res.status(500).json({ error: "Lỗi hệ thống khi tra cứu SKU" });
    }
});

// 3. API Trừ số lượng (CHỈ CHO PHÉP ORDER SERVICE GỌI - Kiểm tra qua mTLS)
app.patch('/api/v1/products/:sku/reduce-stock', requireInternalMTLS, async (req, res) => {
    const { qty } = req.body;
    const { sku } = req.params;
    try {
        const query = `UPDATE products SET stock = stock - $1 WHERE sku = $2 AND stock >= $1 RETURNING *`;
        const { rows } = await pool.query(query, [qty, sku]);
        if (rows.length === 0) return res.status(400).json({ error: "Hết hàng hoặc số lượng tồn kho không đủ!" });
        res.status(200).json({ message: "Trừ kho thành công", product: rows[0] });
    } catch (err) { res.status(500).json({ error: "Lỗi DB khi cập nhật kho" }); }
});

// 4. API Hoàn số lượng (CHỈ CHO PHÉP ORDER SERVICE GỌI)
app.patch('/api/v1/products/:sku/add-stock', requireInternalMTLS, async (req, res) => {
    const { qty } = req.body;
    const { sku } = req.params;
    try {
        const query = `UPDATE products SET stock = stock + $1 WHERE sku = $2 RETURNING *`;
        const { rows } = await pool.query(query, [qty, sku]);
        if (rows.length === 0) return res.status(404).json({ error: "Không tìm thấy sản phẩm để hoàn kho!" });
        res.status(200).json({ message: "Hoàn kho thành công", product: rows[0] });
    } catch (err) { res.status(500).json({ error: "Lỗi DB khi hoàn kho" }); }
});

// ==========================================
// D. KHỞI ĐỘNG HỆ THỐNG CÙNG mTLS
// ==========================================
async function bootstrap() {
    try {
        // 1. Lấy Token và DB URL
        const VAULT_TOKEN = await getVaultToken();
        const dbUrl = await getDbUrlFromVault(VAULT_TOKEN);
        
        if (!dbUrl) {
            console.error("❌ KHÔNG THỂ KHỞI ĐỘNG: Không lấy được DB URL từ Vault!");
            process.exit(1); 
        }

        // 2. Lấy chứng chỉ Động từ Vault PKI
        const certs = await getDynamicCertFromVault(VAULT_TOKEN);

        // 3. Khởi tạo kết nối DB (Đã fix lỗi biến secrets)
        pool = new Pool({ 
            connectionString: dbUrl, 
            ssl: { 
                rejectUnauthorized: true,    
                ca: fs.readFileSync('./certs/neon-root-ca.pem').toString() 
            }
        });

        // 4. Cấu hình HTTPS & Trust Store (Cây niềm tin)
        const options = {
            key: certs.key,
            cert: certs.cert,
            ca: [
                fs.readFileSync('./certs/ca.crt'),      // Trust Root CA
                fs.readFileSync('./certs/int-ca.crt'),  // Trust Kong Gateway (CA Tĩnh)
                certs.dynamic_ca                        // Trust Order Service (CA Động)
            ],
            requestCert: true,
            rejectUnauthorized: true 
        };

        // 5. Bật Server
        const PORT = process.env.PORT || 3001;
        https.createServer(options, app).listen(PORT, '0.0.0.0', () => {
            console.log('============================================');
            console.log(`🔒 Product Service đã khởi động (Pure ECC) ở cổng ${PORT}`);
            console.log(`📜 Đã lấy chứng chỉ mTLS động từ Vault.`);
            console.log(`🚀 Đã kết nối Database thành công!`);
            console.log('============================================');
        });
    } catch (err) {
        console.error("❌ Fatal Error trong qua trinh Boot:", err);
        process.exit(1);
    }
}

// Middleware Chốt chặn siêu cấp bảo mật
function requireInternalMTLS(req, res, next) {
    const cert = req.socket.getPeerCertificate();
    
    if (!req.client.authorized || !cert || !cert.subject) {
        return res.status(403).json({ error: "Forbidden: Yêu cầu chứng chỉ mTLS hợp lệ!" });
    }

    // [BẢO MẬT CHIỀU SÂU]: Chỉ đích danh 'backend-order-api' mới được phép trừ/hoàn kho
    if (cert.subject.CN !== 'backend-order-api') {
        console.warn(`⚠️ Cảnh báo bảo mật: Có kẻ gian (${cert.subject.CN}) định can thiệp kho hàng!`);
        return res.status(403).json({ error: "Forbidden: Bạn không có quyền can thiệp kho hàng!" });
    }

    next();
}

bootstrap();