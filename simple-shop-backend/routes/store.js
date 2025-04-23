// routes/store.js
const express = require('express');
const router = express.Router();
const pool = require('../db');

router.get('/', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM store_info');

    if (rows.length === 0) {
      return res.status(404).json({ message: 'Store information not found' });
    }
    return res.json(rows[0]);
  } catch (error) {
    console.error('Error getting store information:', error);
    return res.status(500).json({ message: 'Inside server error' });
  }
});

module.exports = router;
