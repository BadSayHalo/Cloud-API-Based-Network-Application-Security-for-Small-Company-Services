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
const VAULT_ADDR = process.env.VAULT_ADDR || 'http://vault-server:8200';
let pool; // Biến kết nối Database

// ==========================================
// B. LẤY DATABASE URL TỪ VAULT 
// ==========================================
async function getDbUrlFromVault() {
    const tokenPath = '/app/vault-token-share/.vault-token';
    
    // Đợi Vault Agent lấy Token về
    for (let i = 0; i < 10; i++) {
        if (fs.existsSync(tokenPath)) break;
        console.log("⏳ Đang đợi Vault Agent cấp Token cho Product Service...");
        await new Promise(res => setTimeout(res, 1000));
    }

    try {
        const VAULT_TOKEN = fs.readFileSync(tokenPath, 'utf8').trim();
        
        // Gọi ké sang path của order-service để lấy chung link Database
        const response = await axios.get(`${VAULT_ADDR}/v1/secret/data/order-service`, {
            headers: { 'X-Vault-Token': VAULT_TOKEN }
        });
        
        // Chỉ trích xuất đúng DATABASE_URL, không cần lấy Encryption Key
        return response.data.data.data.DATABASE_URL;
    } catch (error) {
        console.error("❌ [VAULT] Lỗi lấy DB URL:", error.message);
        return null;
    }
}

// ==========================================
// C. API ROUTES
// ==========================================

// 1. API cho Khách vãng lai xem danh sách Laptop (Đi qua Kong, mở tự do)
app.get('/api/v1/products', async (req, res) => {
    try {
        // Lấy tất cả sản phẩm, sắp xếp theo tên
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

// 2. API Nội bộ (East-West Traffic): Order-Service gọi sang để check giá
app.get('/api/v1/products/:sku', async (req, res) => {
    try {
        const sku = req.params.sku;
        // Dùng $1 để chống SQL Injection tuyệt đối
        const { rows } = await pool.query('SELECT * FROM products WHERE sku = $1', [sku]);
        
        if (rows.length === 0) {
            return res.status(404).json({ error: `Không tìm thấy sản phẩm với mã SKU: ${sku}` });
        }
        
        res.status(200).json({ data: rows[0] });
    } catch (err) {
        console.error("Lỗi lấy chi tiết sản phẩm:", err.message);
        res.status(500).json({ error: "Lỗi hệ thống khi tra cứu SKU" });
    }
});

// API: Trừ số lượng tồn kho (Chỉ cho phép gọi nội bộ)
app.patch('/api/v1/products/:sku/reduce-stock', async (req, res) => {
    const { qty } = req.body;
    const { sku } = req.params;

    try {
        // Câu lệnh SQL thông minh: Chỉ trừ nếu stock >= qty
        const query = `
            UPDATE products 
            SET stock = stock - $1 
            WHERE sku = $2 AND stock >= $1 
            RETURNING *
        `;
        const { rows } = await pool.query(query, [qty, sku]);

        if (rows.length === 0) {
            return res.status(400).json({ error: "Hết hàng hoặc số lượng tồn kho không đủ!" });
        }

        res.status(200).json({ message: "Trừ kho thành công", product: rows[0] });
    } catch (err) {
        res.status(500).json({ error: "Lỗi DB khi cập nhật kho" });
    }
});

// API: Cộng lại số lượng tồn kho (Dùng khi hủy đơn)
app.patch('/api/v1/products/:sku/add-stock', async (req, res) => {
    const { qty } = req.body;
    const { sku } = req.params;

    try {
        const query = `
            UPDATE products 
            SET stock = stock + $1 
            WHERE sku = $2 
            RETURNING *
        `;
        const { rows } = await pool.query(query, [qty, sku]);

        if (rows.length === 0) {
            return res.status(404).json({ error: "Không tìm thấy sản phẩm để hoàn kho!" });
        }

        res.status(200).json({ message: "Hoàn kho thành công", product: rows[0] });
    } catch (err) {
        res.status(500).json({ error: "Lỗi DB khi hoàn kho" });
    }
});

// ==========================================
// D. KHỞI ĐỘNG HỆ THỐNG CÙNG mTLS
// ==========================================
async function bootstrap() {
    const dbUrl = await getDbUrlFromVault();
    
    if (!dbUrl) {
        console.error("❌ KHÔNG THỂ KHỞI ĐỘNG: Không lấy được DB URL từ Vault!");
        process.exit(1); 
    }

    // 1. Khởi tạo kết nối DB bằng Pool
    pool = new Pool({ 
        connectionString: dbUrl, 
        ssl: { rejectUnauthorized: false } // Rất quan trọng khi dùng Cloud DB
    });

    // 2. Cấu hình HTTPS (Đọc chứng chỉ mTLS)
    const options = {
        key: fs.readFileSync('./certs/node.key'),
        cert: fs.readFileSync('./certs/node.crt'),
        ca: [fs.readFileSync('./certs/ca.crt')],
        requestCert: true,
        rejectUnauthorized: true
    };

    // 3. Bật Server
    const PORT = process.env.PORT || 3001;
    https.createServer(options, app).listen(PORT, '0.0.0.0', () => {
        console.log(`🔒 Product Service đã "sống" ở cổng ${PORT}`);
        console.log(`🚀 Đã kết nối Database thành công qua HashiCorp Vault!`);
    });
}

bootstrap();