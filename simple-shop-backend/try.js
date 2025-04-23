// hash.js
const bcrypt = require('bcrypt');

async function run() {
  const plain = 'qwerty';    // ваш пароль
  const hash = await bcrypt.hash(plain, 10); // соль 10 раундов
  console.log(hash);
}

run();
