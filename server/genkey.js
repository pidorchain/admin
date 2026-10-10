// Создаёт пару ключей Ed25519 для подписи ответов сервера.
// Запуск: node genkey.js
//   BAN_SIGN_KEY  → в переменные окружения сервера (Render → Environment). Секрет, никому не показывать!
//   PUBLIC_KEY    → в лаунчер: src/profile.js, константа PUBKEY. Он не секретный.
const { generateKeyPairSync } = require('crypto');
const { publicKey, privateKey } = generateKeyPairSync('ed25519');
console.log('BAN_SIGN_KEY=' + privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64'));
console.log('PUBLIC_KEY=' + publicKey.export({ format: 'der', type: 'spki' }).toString('base64'));
