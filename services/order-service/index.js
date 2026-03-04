const express = require('express');
const app = express();
app.use(express.json());

const orders = [
    { id: '101', userId: 'userA', item: 'Laptop Dell', price: 1200, status: 'Shipped' },
    { id: '102', userId: 'userB', item: 'MacBook Pro', price: 2000, status: 'Processing' }
];

app.get('/orders', (req, res) => {
    res.json(orders); 
});

app.get('/orders/:id', (req, res) => {
    const orderId = req.params.id;
    const order = orders.find(o => o.id === orderId);
    
    if (order) {
        res.json(order);
    } else {
        res.status(404).json({ error: 'Order not found' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Order Service running on port ${PORT}`));