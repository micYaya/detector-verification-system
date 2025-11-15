// 根据环境加载对应的环境变量
require('dotenv').config({
    path:
        process.env.NODE_ENV === 'production'
            ? './.env.production'
            : './.env.development',
});
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const session = require('express-session');
const fs = require('fs');
const path = require('path');
const compression = require('compression');
const cookieParser = require('cookie-parser');
const config = require('./config/config');

const app = express();
const port = 3000;

// 配置跨域中间件，启用跨域Cookie支持
app.use(
    cors({
        origin: function (origin, callback) {
            const envOrigins =
                process.env.ALLOWED_ORIGINS || config.config.server.frontendUrl;
            const allowedOrigins = envOrigins.split(',').map(o => o.trim());
            if (!origin || allowedOrigins.includes(origin)) {
                callback(null, true);
            } else {
                callback(null, origin);
            }
        },
        credentials: true,
        methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization'],
    })
);
// 解析JSON数据中间件
app.use(bodyParser.json());

// 配置Cookie解析中间件
app.use(cookieParser(config.config.jwtSecretKey)); // 使用JWT密钥作为cookie签名密钥

// 配置Session中间件，用于管理用户会话，状态持久化
app.use(
    session({
        secret: 'yayamic',
        resave: false,
        saveUninitialized: true,
        cookie: {
            maxAge: 24 * 60 * 60 * 1000, // 会话有效期
        },
    })
);

// 配置压缩中间件,gzip压缩响应数据
app.use(compression());

const authenticateToken = require('./middlewares/auth'); // 引入 token 验证中间件
// 跳过特定路由的 token 验证
app.use((req, res, next) => {
    const publicRoutes = [
        '/api/sendcode',
        '/api/login_sms',
        '/api/register',
        '/api/check_user',
        '/api/reset_password',
        '/api/refresh_token',
    ]; // 不需要验证的路由
    if (publicRoutes.includes(req.path)) {
        return next(); // 跳过验证
    }
    authenticateToken(req, res, next); // 其他路由需要验证
});

// 自动加载routes文件夹中的所有路由
fs.readdirSync(path.join(__dirname, 'routes')).forEach(file => {
    const route = require(`./routes/${file}`);
    app.use(route);
});

const errorHandler = require('./middlewares/errorHandler');
// 挂载全局错误处理中间件
app.use(errorHandler);

// 根据环境配置启动HTTP或HTTPS服务器
if (config.config.server.https.enabled) {
    // HTTPS服务器
    const https = require('https');
    const fs = require('fs');

    try {
        // 读取SSL证书
        const privateKey = fs.readFileSync(
            config.config.server.https.key,
            'utf8'
        );
        const certificate = fs.readFileSync(
            config.config.server.https.cert,
            'utf8'
        );
        const credentials = { key: privateKey, cert: certificate };

        // 创建HTTPS服务器
        const httpsServer = https.createServer(credentials, app);
        httpsServer.listen(config.config.server.port, () => {
            console.log(`HTTPS服务器运行在端口 ${config.config.server.port}`);
        });
    } catch (error) {
        console.error('启动HTTPS服务器失败:', error);
        console.log('回退到HTTP服务器...');
        app.listen(config.config.server.port, () => {
            console.log(`HTTP服务器运行在端口 ${config.config.server.port}`);
        });
    }
} else {
    // HTTP服务器
    app.listen(config.config.server.port, () => {
        console.log(`HTTP服务器运行在端口 ${config.config.server.port}`);
    });
}
