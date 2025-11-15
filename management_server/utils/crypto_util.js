/**
 * 加密工具模块 - 用于敏感信息加密传输
 */
const CryptoJS = require('crypto-js');
const config = require('../config/config');

// 加密密钥，生产环境应从环境变量获取
const SECRET_KEY =
    config.config.cryptoSecretKey || 'your-secret-key-for-encryption';

/**
 * AES加密函数
 * @param {string} plainText - 需要加密的明文
 * @returns {string} - 加密后的密文
 */
function encrypt(plainText) {
    if (!plainText) return '';
    const cipherText = CryptoJS.AES.encrypt(plainText, SECRET_KEY).toString();
    return cipherText;
}

/**
 * AES解密函数
 * @param {string} cipherText - 需要解密的密文
 * @returns {string} - 解密后的明文
 */
function decrypt(cipherText) {
    if (!cipherText) return '';
    const bytes = CryptoJS.AES.decrypt(cipherText, SECRET_KEY);
    const plainText = bytes.toString(CryptoJS.enc.Utf8);
    return plainText;
}

/**
 * RSA公钥加密（前端使用）
 * 注意：实际项目中应使用真实的RSA密钥对
 * 这里仅作为示例，实际应用中应使用更安全的密钥管理方式
 */
const RSA_PUBLIC_KEY = `
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCxfMJSOAF8mIzJhHQCcYqaIjuW
5Jf8yjHfEVwXuUQrNbTG5t+2SyAqOHwzXn3qMD1vBhikzxKUYxSGK3KDMFEOCp8x
9+bP0ZFMXfQeuW1AvVUqI5QnKjpLz8YcMHftPvZaNLQVrIyTmKPaIJ5zxjJP/1Zc
y9QxPpQrJ8VO+yfGJQIDAQAB
-----END PUBLIC KEY-----
`;

/**
 * 验证加密数据对象
 * @param {Object} encryptedData - 加密的数据对象
 * @returns {boolean} - 是否是有效的加密数据
 */
function validateEncryptedData(encryptedData) {
    return (
        encryptedData && typeof encryptedData === 'object' && encryptedData.data
    );
}

module.exports = {
    encrypt,
    decrypt,
    validateEncryptedData,
    RSA_PUBLIC_KEY,
};
