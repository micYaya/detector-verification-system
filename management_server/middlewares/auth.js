const jwt = require('jsonwebtoken'); // JWT进行验证
const config = require('../config/config');
// 验证accessToken的中间件
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization']; // 从请求头中获取 Authorization 字段
    const token = authHeader && authHeader.split(' ')[1]; // Bearer <token>

    if (!token) {
        return res.status(401).json({ error: '未提供 Token，访问被拒绝' });
    }
    // console.log(config.config.jwtSecretKey);
    // process.env.JWT_SECRET
    jwt.verify(token, config.config.jwtSecretKey, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Token 无效或已过期' });
        }
        req.user = user; // 将解码后的用户信息附加到请求对象
        next(); // 继续执行后续逻辑
    });
}

module.exports = authenticateToken;
