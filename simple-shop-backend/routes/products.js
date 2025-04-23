// routes/products.js
const express = require('express');
const router = express.Router();
const pool = require('../db');

router.get('/', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM products');
    return res.json(rows);
  } catch (error) {
    console.error('Error while receiving goods:', error);
    return res.status(500).json({ message: 'Inside server error' });
  }
});

module.exports = router;
