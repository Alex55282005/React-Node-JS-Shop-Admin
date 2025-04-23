// authMiddleware.js
const jwt = require('jsonwebtoken');
const JWT_SECRET = 'SUPER_SECRET_KEY';

module.exports = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ message: 'Token not transferred' });
  }

  const token = authHeader.split(' ')[1]; // получаем сам токен

  if (!token) {
    return res.status(401).json({ message: 'Token not transferred' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    // Сохраняем данные из токена в req.user
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Wrong token' });
  }
};
