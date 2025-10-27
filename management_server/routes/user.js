const fs = require('fs');
const path = require('path');
const express = require('express');
// const { v4: uuidv4 } = require('uuid'); // 生成唯一 ID
const bcrypt = require('bcryptjs');

const userRouter = express.Router();
const usersFile = path.join(__dirname, '../db/users.json');
// const authenticateToken = require('../middlewares/auth'); // 引入token验证中间件
// // 应用中间件
// userRouter.use(authenticateToken);

// 读取用户数据
function readUsers() {
  const data = fs.readFileSync(usersFile, 'utf-8');
  return JSON.parse(data);
}

// 写入用户数据
function writeUsers(data) {
  fs.writeFileSync(usersFile, JSON.stringify(data, null, 2), 'utf-8');
}

// 搜索获取所有用户列表
userRouter.get('/api/users', (req, res) => {
    // console.log(1);
    const users = readUsers();
    const result = users.map(({ id, phone, createTime, nickname, role }) => ({
      id,
      phone,
      createTime,
      nickname,
      role
    }));
  
    res.json({
      total: result.length,
      list: result
    });
});
  
  
// 获取单个用户
userRouter.get('/api/users/:id', (req, res) => {
  const users = readUsers();
  const user = users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: '用户不存在' });
  res.json(user);
});

// 添加用户
userRouter.post('/api/users', async (req, res) => {
  const users = readUsers();
  const { nickname, phone, role } = req.body;

  if (!nickname || !role || !phone) {
    return res.status(400).json({ error: '缺少必要字段' });
  }

  if (users.find(u => u.phone === phone)) {
    return res.status(400).json({ error: '手机号已存在' });
  }

  const id = Date.now().toString();
  const now = Date.now();
  const defaultPassword = await bcrypt.hash('123456', 10); // 默认密码

  const newUser = {
    id,
    phone,
    password: defaultPassword,
    createTime: now,
    lastLogin: now,
    nickname,
    role
  };

  users.push(newUser);
  writeUsers(users);
  res.status(201).json(newUser);
});

// 更新用户
userRouter.put('/api/users/:id', (req, res) => {
  const users = readUsers();
  const { nickname, phone, role } = req.body;
  const userIndex = users.findIndex(u => u.id === req.params.id);

  if (userIndex === -1) {
    return res.status(404).json({ error: '用户不存在' });
  }

  users[userIndex] = {
    ...users[userIndex],
    nickname,
    phone,
    role
  };

  writeUsers(users);
  res.json(users[userIndex]);
});

// 删除用户
userRouter.delete('/api/users/:id', (req, res) => {
  const users = readUsers();
  const id = req.params.id;

  const index = users.findIndex(u => u.id === id);
  if (index === -1) {
    return res.status(404).json({ error: '用户不存在' });
  }

  users.splice(index, 1);
  writeUsers(users);
  res.json({ message: '删除成功' });
});

module.exports = userRouter;