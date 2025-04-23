// routes/auth.js
const express = require('express');
const router = express.Router();
const { body, validationResult } = require('express-validator'); // To protect the sql injections
const pool = require('../db'); 
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const JWT_SECRET = 'SUPER_SECRET_KEY';

// Validation for /register
const registerValidation = [
  body('email')
    .isEmail().withMessage('Invalid email format.'),
  body('password')
    .isLength({ min: 6 }).withMessage('Password must be at least 6 characters long.'),
  body('name')
    .notEmpty().withMessage('Name is required.')
];

// Validation for  /login
const loginValidation = [
  body('email')
    .isEmail().withMessage('Invalid email format.'),
  body('password')
    .notEmpty().withMessage('Password is required.')
];

// ---------------------- Register ----------------------
router.post('/register', registerValidation, async (req, res) => {
  try {
    // Check the result of validation
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password, name } = req.body;

    // Using Parameterized Query (?) Against SQL Injections
    const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (rows.length > 0) {
      return res.status(400).json({ message: 'This email is already registered' });
    }

    // Hashing the password
    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.query(
      'INSERT INTO users (email, password, name) VALUES (?, ?, ?)',
      [email, hashedPassword, name]
    );

    return res.status(201).json({ message: 'Registration is successful' });
  } catch (error) {
    console.error('Registration error:', error);
    return res.status(500).json({ message: 'Inside server error' });
  }
});

// ---------------------- Login ----------------------
router.post('/login', loginValidation, async (req, res) => {
  try {
    // Check the result of validation
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (rows.length === 0) {
      return res.status(401).json({ message: 'Wrong email or password' });
    }

    const user = rows[0];
    // Compare password hash
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Wrong email or password' });
    }

    // Generate a JWT token
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
      expiresIn: '1d',
    });

    return res.json({
      message: 'Login is successful',
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
      },
    });
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ message: 'Inside server error' });
  }
});

module.exports = router;
