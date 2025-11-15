const mysql = require('mysql2/promise');

// 基础环境校验，避免出现 user '' using password NO 这类错误
const requiredEnv = ['DB_HOST', 'DB_PORT', 'DB_USER', 'DB_PASSWORD', 'DB_NAME'];
const missing = requiredEnv.filter(
    k => !process.env[k] || process.env[k].trim() === ''
);
if (missing.length) {
    console.error(
        `[DB] 缺少必要环境变量: ${missing.join(', ')}。请在 .env.${process.env.NODE_ENV || 'development'} 中配置。`
    );
}

// 创建数据库连接池
const pool = mysql.createPool({
    host: process.env.DB_HOST || '127.0.0.1',
    port: Number(process.env.DB_PORT || 3306),
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'management_db',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
});

module.exports = pool;
