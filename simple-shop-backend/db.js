// db.js
const mysql = require('mysql2/promise');

const pool = mysql.createPool({
  host: '127.0.0.1',   // или 'localhost'
  port: 3306,         // Порт MySQL, обычно 3306
  user: 'root',       // Ваш пользователь MySQL
  password: 'qwerty', // Если пароля нет, укажите ''
  database: 'simple_shop',       // Название вашей БД
  connectionLimit: 10,
});

module.exports = pool;
