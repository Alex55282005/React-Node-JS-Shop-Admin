// routes/admin.js
const express = require('express');
const router = express.Router();
const pool = require('../db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');

const JWT_SECRET = 'SUPER_SECRET_KEY';

// Middleware для проверки JWT-токена администратора
function adminAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader)
    return res.status(401).json({ message: 'No token provided' });
    
  const token = authHeader.split(' ')[1];
  if (!token)
    return res.status(401).json({ message: 'Token missing' });
    
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.admin = decoded; // decoded имеет поля { id, email, role }
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Invalid token' });
  }
}

// Middleware, разрешающий действия только для администраторов с ролью "high_admin"
function highAdminOnly(req, res, next) {
  if (req.admin && req.admin.role === 'high_admin') {
    next();
  } else {
    return res
      .status(403)
      .json({ message: 'Access denied. Requires high_admin role.' });
  }
}

// GET /api/admin/me — получить данные текущего администратора
router.get('/me', adminAuth, async (req, res) => {
  try {
    // req.admin заполняется в middleware adminAuth и содержит { id, email, role }
    const adminId = req.admin.id;

    const [rows] = await pool.query(
      'SELECT id, name, email, role, created_at FROM admins WHERE id = ?',
      [adminId]
    );
    if (rows.length === 0) {
      return res.status(404).json({ message: 'Admin not found' });
    }

    return res.json(rows[0]);
  } catch (err) {
    console.error('Error fetching admin data:', err);
    return res.status(500).json({ message: 'Server error' });
  }
});


/*===========================
  Admin Login Endpoint
===========================*/
// POST /api/admin/login
router.post(
  '/login',
  [
    body('email').isEmail().withMessage('Invalid email'),
    body('password').notEmpty().withMessage('Password is required'),
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty())
        return res.status(400).json({ errors: errors.array() });

      const { email, password } = req.body;

      // Предполагаем, что таблица Admins имеет столбцы: id, name, email, password, role, created_at
      const [admins] = await pool.query('SELECT * FROM Admins WHERE email = ?', [email]);
      if (admins.length === 0)
        return res.status(401).json({ message: 'Invalid email or password' });

      const admin = admins[0];

      const isMatch = await bcrypt.compare(password, admin.password);
      if (!isMatch)
        return res.status(401).json({ message: 'Invalid email or password' });

      const token = jwt.sign(
        { id: admin.id, email: admin.email, role: admin.role },
        JWT_SECRET,
        { expiresIn: '1d' }
      );

      return res.json({
        message: 'Admin login successful',
        token,
        admin: { id: admin.id, name: admin.name, email: admin.email, role: admin.role },
      });
    } catch (error) {
      console.error('Admin login error:', error);
      return res.status(500).json({ message: 'Server error' });
    }
  }
);

/*===========================
  Product Management
===========================*/
// GET /api/admin/products — Получить все продукты
router.get('/products', adminAuth, async (req, res) => {
  try {
    const [products] = await pool.query('SELECT * FROM products');
    return res.json(products);
  } catch (error) {
    console.error('Error fetching products:', error);
    return res.status(500).json({ message: 'Server error' });
  }
});

// POST /api/admin/products — Добавить новый продукт
router.post(
  '/products',
  adminAuth,
  [
    body('title').notEmpty().withMessage('Title is required'),
    body('price').isDecimal().withMessage('Price must be a number'),
    body('description').optional(),
    body('image_url').optional(),
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty())
        return res.status(400).json({ errors: errors.array() });

      const { title, description, price, image_url } = req.body;
      const [result] = await pool.query(
        'INSERT INTO products (title, description, price, image_url) VALUES (?, ?, ?, ?)',
        [title, description, price, image_url]
      );
      return res.status(201).json({ message: 'Product added successfully', productId: result.insertId });
    } catch (error) {
      console.error('Error adding product:', error);
      return res.status(500).json({ message: 'Server error' });
    }
  }
);

// PUT /api/admin/products/:id — Редактировать продукт
router.put(
  '/products/:id',
  adminAuth,
  [
    body('title').optional().notEmpty().withMessage('Title cannot be empty'),
    body('price').optional().isDecimal().withMessage('Price must be a number'),
    body('description').optional(),
    body('image_url').optional(),
  ],
  async (req, res) => {
    try {
      const { id } = req.params;
      const { title, description, price, image_url } = req.body;
      const [result] = await pool.query(
        'UPDATE products SET title = COALESCE(?, title), description = COALESCE(?, description), price = COALESCE(?, price), image_url = COALESCE(?, image_url) WHERE id = ?',
        [title, description, price, image_url, id]
      );
      if (result.affectedRows === 0)
        return res.status(404).json({ message: 'Product not found' });
      return res.json({ message: 'Product updated successfully' });
    } catch (error) {
      console.error('Error updating product:', error);
      return res.status(500).json({ message: 'Server error' });
    }
  }
);

// DELETE /api/admin/products/:id — Удалить продукт
router.delete('/products/:id', adminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const [result] = await pool.query('DELETE FROM products WHERE id = ?', [id]);
    if (result.affectedRows === 0)
      return res.status(404).json({ message: 'Product not found' });
    return res.json({ message: 'Product deleted successfully' });
  } catch (error) {
    console.error('Error deleting product:', error);
    return res.status(500).json({ message: 'Server error' });
  }
});

/*===========================
  Admin Management
===========================*/
// GET /api/admin/admins — Получить всех администраторов
router.get('/admins', adminAuth, async (req, res) => {
  try {
    const [admins] = await pool.query('SELECT id, name, email, role, created_at FROM Admins');
    return res.json(admins);
  } catch (error) {
    console.error('Error fetching admins:', error);
    return res.status(500).json({ message: 'Server error' });
  }
});

// POST /api/admin/admins — Добавить нового администратора (только для high_admin)
router.post(
  '/admins',
  adminAuth,
  highAdminOnly,
  [
    body('name').notEmpty().withMessage('Name is required'),
    body('email').isEmail().withMessage('Valid email is required'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
    body('role').notEmpty().withMessage('Role is required'), // Например, "admin" или "high_admin"
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty())
        return res.status(400).json({ errors: errors.array() });
      const { name, email, password, role } = req.body;
      const hashedPassword = await bcrypt.hash(password, 10);
      const [result] = await pool.query(
        'INSERT INTO Admins (name, email, password, role) VALUES (?, ?, ?, ?)',
        [name, email, hashedPassword, role]
      );
      return res.status(201).json({ message: 'Admin added successfully', adminId: result.insertId });
    } catch (error) {
      console.error('Error adding admin:', error);
      return res.status(500).json({ message: 'Server error' });
    }
  }
);

/*===========================
  User Management
===========================*/
// GET /api/admin/users — Получить всех пользователей
router.get('/users', adminAuth, async (req, res) => {
  try {
    const [users] = await pool.query('SELECT id, email, name, created_at FROM users');
    return res.json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    return res.status(500).json({ message: 'Server error' });
  }
});

// POST /api/admin/users — Добавить нового пользователя (админ может создать аккаунт)
router.post(
  '/users',
  adminAuth,
  [
    body('email').isEmail().withMessage('Valid email is required'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
    body('name').notEmpty().withMessage('Name is required'),
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty())
        return res.status(400).json({ errors: errors.array() });
      const { email, password, name } = req.body;
      // Проверка на дублирование email
      const [existing] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
      if (existing.length > 0)
        return res.status(400).json({ message: 'This email is already registered' });
      const hashedPassword = await bcrypt.hash(password, 10);
      const [result] = await pool.query(
        'INSERT INTO users (email, password, name) VALUES (?, ?, ?)',
        [email, hashedPassword, name]
      );
      return res.status(201).json({ message: 'User added successfully', userId: result.insertId });
    } catch (error) {
      console.error('Error adding user:', error);
      return res.status(500).json({ message: 'Server error' });
    }
  }
);

// PUT /api/admin/users/:id — Редактировать пользователя
router.put(
  '/users/:id',
  adminAuth,
  [
    body('email').optional().isEmail().withMessage('Valid email is required'),
    body('password').optional().isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
    body('name').optional().notEmpty().withMessage('Name is required'),
  ],
  async (req, res) => {
    try {
      const { id } = req.params;
      const { email, password, name } = req.body;
      let hashedPassword = null;
      if (password) {
        hashedPassword = await bcrypt.hash(password, 10);
      }
      const [result] = await pool.query(
        'UPDATE users SET email = COALESCE(?, email), password = COALESCE(?, password), name = COALESCE(?, name) WHERE id = ?',
        [email, hashedPassword, name, id]
      );
      if (result.affectedRows === 0)
        return res.status(404).json({ message: 'User not found' });
      return res.json({ message: 'User updated successfully' });
    } catch (error) {
      console.error('Error updating user:', error);
      return res.status(500).json({ message: 'Server error' });
    }
  }
);

// DELETE /api/admin/users/:id — Удалить пользователя
router.delete('/users/:id', adminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const [result] = await pool.query('DELETE FROM users WHERE id = ?', [id]);
    if (result.affectedRows === 0)
      return res.status(404).json({ message: 'User not found' });
    return res.json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Error deleting user:', error);
    return res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;
