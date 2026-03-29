const express = require('express');
const { Pool } = require('pg');

const app = express();
app.use(express.json());

const pool = new Pool({
    user: process.env.DB_USER || 'postgres',
    host: process.env.DB_HOST || 'app-db',
    database: process.env.DB_NAME || 'laptop_store',
    password: process.env.DB_PASSWORD || 'postgres_db_password',
    port: 5432,
});

pool.connect()
    .then(() => console.log('✅ Đã kết nối thành công với PostgreSQL!'))
    .catch(err => console.error('❌ Lỗi kết nối Database:', err.stack));

// API 1: Lấy danh sách đơn hàng của bản thân
app.get('/api/v1/orders', async (req, res) => {
    try {
        const currentUserId = req.headers['x-consumer-username'];
        if (!currentUserId) {
            return res.status(401).json({ error: 'Unauthorized - Missing Token Identity' });
        }

        const query = 'SELECT * FROM orders WHERE user_id = $1 ORDER BY order_date DESC';
        const result = await pool.query(query, [currentUserId]);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// API 2: Xem chi tiết đơn hàng (Có cơ chế chống BOLA)
app.get('/api/v1/orders/:id', async (req, res) => {
    try {
        const orderId = req.params.id;
        const currentUserId = req.headers['x-consumer-username'];

        if (!currentUserId) return res.status(401).json({ error: 'Unauthorized' });

        const query = 'SELECT * FROM orders WHERE id = $1';
        const result = await pool.query(query, [orderId]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Order not found' });
        }

        const order = result.rows[0];

        // CHỐNG LỖ HỔNG BOLA: Chặn nếu người xem không phải chủ đơn hàng
        if (order.user_id.toString() !== currentUserId.toString()) {
            return res.status(403).json({ 
                error: 'Forbidden - BOLA Attempt Detected! You do not own this order.' 
            });
        }

        res.json(order);
    } catch (err) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Order Service running on port ${PORT}`));