require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const session = require('express-session');
const fs = require('fs');
const path = require('path');
const compression = require('compression');

const app = express();
const port = 3000;

// 配置跨域中间件
app.use(cors());
// app.use(cors({
//   origin: 'http://localhost:5173',
//   credentials: true
// })); 
// 解析JSON数据中间件
app.use(bodyParser.json());

// 配置Session中间件，用于管理用户会话，状态持久化
app.use(session({
  secret: 'yayamic',
  resave: false,
  saveUninitialized: true,
  cookie: { 
    maxAge: 24 * 60 * 60 * 1000 // 会话有效期
  }
}));

// 配置压缩中间件,gzip压缩响应数据
app.use(compression());

const authenticateToken = require('./middlewares/auth'); // 引入 token 验证中间件
// 跳过特定路由的 token 验证
app.use((req, res, next) => {
  const publicRoutes = ['/api/sendcode', '/api/login_sms', '/api/register', '/api/check_user', '/api/reset_password']; // 不需要验证的路由
  if (publicRoutes.includes(req.path)) {
    return next(); // 跳过验证
  }
  authenticateToken(req, res, next); // 其他路由需要验证
});

// 自动加载routes文件夹中的所有路由
fs.readdirSync(path.join(__dirname, 'routes')).forEach((file) => {
  const route = require(`./routes/${file}`);
  app.use(route);
});

const errorHandler = require('./middlewares/errorHandler');
// 挂载全局错误处理中间件
app.use(errorHandler);

// 启动服务器
app.listen(port, () => {
    console.log(`服务器运行在端口 ${port}`);
});