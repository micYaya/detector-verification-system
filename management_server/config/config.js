// 根据环境加载对应的环境变量
require('dotenv').config({
    path:
        process.env.NODE_ENV === 'production'
            ? './.env.production'
            : './.env.development',
});

const config = {
    server: {
        port: process.env.PORT || 3000,
        frontendUrl: process.env.FRONTEND_URL || 'http://localhost:5173',
        // HTTPS配置
        https: {
            enabled: process.env.ENABLE_HTTPS === 'true' || false,
            key: process.env.HTTPS_KEY_PATH || './ssl/private.key',
            cert: process.env.HTTPS_CERT_PATH || './ssl/certificate.crt',
        },
    },
    // 为了兼容旧代码，保留顶层 jwtSecretKey 字段
    jwtSecretKey: process.env.JWT_SECRET_KEY || 'yayamic1',
    jwt: {
        secretKey: process.env.JWT_SECRET_KEY || 'yayamic1',
        accessTokenExpiry: process.env.ACCESS_TOKEN_EXPIRY || '1h',
        refreshTokenExpiry: process.env.REFRESH_TOKEN_EXPIRY || '7d',
    },
    crypto: {
        secretKey:
            process.env.CRYPTO_SECRET_KEY ||
            'secure-crypto-key-for-sensitive-data',
    },
    // 环境配置
    environment: process.env.NODE_ENV || 'development',
};

exports.config = config;
