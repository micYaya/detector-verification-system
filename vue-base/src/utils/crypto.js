/**
 * 前端加密工具模块
 * 用于敏感信息加密传输
 */
import CryptoJS from 'crypto-js';

// 加密密钥，实际项目中应从后端获取或使用更安全的密钥交换机制
const SECRET_KEY = 'secure-crypto-key-for-sensitive-data';

/**
 * AES加密函数
 * @param {Object|string} data - 需要加密的数据
 * @returns {string} - 加密后的密文
 */
export function encrypt(data) {
    if (!data) return '';

    // 如果是对象，先转为JSON字符串
    const plainText = typeof data === 'object' ? JSON.stringify(data) : data;
    const cipherText = CryptoJS.AES.encrypt(plainText, SECRET_KEY).toString();
    return cipherText;
}

/**
 * AES解密函数
 * @param {string} cipherText - 需要解密的密文
 * @returns {string} - 解密后的明文
 */
export function decrypt(cipherText) {
    if (!cipherText) return '';
    const bytes = CryptoJS.AES.decrypt(cipherText, SECRET_KEY);
    const plainText = bytes.toString(CryptoJS.enc.Utf8);
    return plainText;
}

/**
 * 加密登录数据
 * @param {Object} loginData - 登录数据对象
 * @returns {Object} - 加密后的数据对象
 */
export function encryptLoginData(loginData) {
    return {
        encrypted: true,
        data: encrypt(loginData),
    };
}

/**
 * 加密注册数据
 * @param {Object} registerData - 注册数据对象
 * @returns {Object} - 加密后的数据对象
 */
export function encryptRegisterData(registerData) {
    return {
        encrypted: true,
        data: encrypt(registerData),
    };
}

export default {
    encrypt,
    decrypt,
    encryptLoginData,
    encryptRegisterData,
};
