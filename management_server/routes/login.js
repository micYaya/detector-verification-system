const express = require('express');
const router = express.Router();
const sms_util = require('../utils/sms_util');
const cryptoUtil = require('../utils/crypto_util');

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('../config/config');
const cookie = require('cookie-parser');

// 内存存储验证码（临时数据，无需持久化）
const users = {};

const fs = require('fs/promises');
const path = require('path');

// 配置
const USER_FILE = path.join(__dirname, '../db/users.json'); // 用户数据文件
const DEFAULT_USERS = []; // 初始数据
// 工具函数
const readUsers = async () => {
    try {
        const data = await fs.readFile(USER_FILE, 'utf8');
        return JSON.parse(data) || DEFAULT_USERS;
    } catch (error) {
        console.error('读取用户文件失败，使用默认数据:', error.message);
        return DEFAULT_USERS;
    }
};

const writeUsers = async users => {
    const data = JSON.stringify(users, null, 2);
    await fs.writeFile(USER_FILE, data, 'utf8');
};

/*
发送验证码短信
*/
router.get('/api/sendcode', async (req, res) => {
    //1. 获取请求参数数据
    var phone = req.query.phone;
    var type = req.query.type;
    // 先检查系统中是否注册过这个手机号
    // 读取用户文件，查找用户
    let usersInfo = await readUsers();
    const userIndex = usersInfo.findIndex(u => u.phone === phone);
    if (userIndex === -1 && type === 'normal') {
        res.send({ code: 1, msg: '系统未注册过该手机号码，请检查' });
        return;
    }
    if (userIndex != -1 && type === 'r') {
        res.send({ code: 1, msg: '系统已存在该手机号码，不可重复注册' });
        return;
    }
    //2. 处理数据
    //生成验证码(4位随机数)
    var code = sms_util.randomCode(4);
    //发送给指定的手机号
    console.log(`向${phone}发送验证码短信: ${code}`);
    sms_util.sendCode(phone, code, function (success) {
        //success表示是否成功
        if (success) {
            users[phone] = code;
            // console.log(users[phone])
            // console.log('保存验证码: ', phone, code)
            res.send({ code: 0 });
        } else {
            //3. 返回响应数据
            res.send({ code: 1, msg: '短信验证码发送失败' });
        }
    });
});

/*
短信登陆
*/
router.post('/api/login_sms', async (req, res) => {
    var phone = req.body.phone;
    var code = req.body.code;
    // console.log('/login_sms', phone, code);
    if (users[phone] != code) {
        res.send({ code: 1, msg: '验证码不正确' });
        return;
    }
    //删除保存的code
    delete users[phone];

    // 读取用户文件
    let usersInfo = await readUsers();

    // 查找用户
    const userIndex = usersInfo.findIndex(u => u.phone === phone);
    let targetUser; // 目标用户
    if (userIndex !== -1) {
        // 已有用户，更新登录时间
        usersInfo[userIndex].lastLogin = Date.now();
        targetUser = usersInfo[userIndex];

        // 短期accessToken，长期refresToken
        const accessToken = jwt.sign(
            { id: targetUser.id, nickname: targetUser.nickname },
            config.config.jwtSecretKey,
            { expiresIn: '1h' } // accessToken 有效期短
        );
        const refreshToken = jwt.sign(
            { id: targetUser.id },
            config.config.jwtSecretKey,
            { expiresIn: '1d' } // refreshToken 更长
        );
        // 设置 session
        req.session.user = {
            id: targetUser.id,
            phone: targetUser.phone,
            password: targetUser.password,
            creatTime: targetUser.creatTime,
            lastLogin: targetUser.lastLogin,
            nickname: targetUser.nickname,
            role: targetUser.role,
            accessToken,
            // refreshToken不再存储在session中
        };

        // 设置 HttpOnly Cookie 存储 refreshToken
        res.cookie('refreshToken', refreshToken, {
            httpOnly: true, // 设置为 HttpOnly，防止前端 JavaScript 访问
            secure: process.env.NODE_ENV === 'production', // 生产环境下仅在 HTTPS 下有效
            sameSite: 'strict', // 防止CSRF攻击
            maxAge: 24 * 60 * 60 * 1000, // 有效期1天
            path: '/', // Cookie 生效路径
        });

        // 写入文件
        try {
            await writeUsers(usersInfo);
            res.send({ code: 0, data: req.session.user });
        } catch (error) {
            console.error('保存用户文件失败:', error.message);
            res.status(500).send({ code: 1, msg: '服务器内部错误' });
        }
    } else {
        res.send({ code: 1, msg: '系统未注册过该手机号码，请检查' });
    }
});

/*
重置密码
*/
router.post('/api/reset_password', async (req, res) => {
    var phone = req.body.phone;
    var code = req.body.code;
    var password = req.body.password;
    // console.log('/reset_password', phone, code, password);
    if (users[phone] != code) {
        res.send({ code: 1, msg: '验证码不正确' });
        return;
    }
    //删除保存的code
    delete users[phone];

    // 读取用户文件
    let usersInfo = await readUsers();
    // 更新用户的密码
    const userIndex = usersInfo.findIndex(u => u.phone === phone);
    if (userIndex !== -1) {
        // 已有用户，更新密码
        let targetUser = usersInfo[userIndex];
        const hashedPassword = bcrypt.hashSync(password, 10);
        targetUser.password = hashedPassword;
        // 设置 session
        req.session.user = {
            id: targetUser.id,
            phone: targetUser.phone,
            password: targetUser.password,
            creatTime: targetUser.creatTime,
            lastLogin: targetUser.lastLogin,
            nickname: targetUser.nickname,
            role: targetUser.role,
        };
        try {
            await writeUsers(usersInfo);
            res.send({ code: 0, data: req.session.user });
        } catch (error) {
            console.error('保存用户文件失败:', error.message);
            res.status(500).send({ code: 1, msg: '服务器内部错误' });
        }
    } else {
        res.send({ code: 1, msg: '系统未注册该手机号码' });
    }
});
/*
注册新用户信息
支持加密传输敏感信息
*/
router.post('/api/register', async (req, res) => {
    try {
        let phone, code, password;

        // 检查是否是加密数据
        if (req.body.encrypted) {
            // 解密数据
            const decryptedData = cryptoUtil.decrypt(req.body.data);
            if (!decryptedData) {
                return res.status(400).send({ code: 1, msg: '数据解密失败' });
            }

            try {
                const parsedData = JSON.parse(decryptedData);
                phone = parsedData.phone;
                code = parsedData.code;
                password = parsedData.password;
            } catch (e) {
                return res
                    .status(400)
                    .send({ code: 1, msg: '解密数据格式错误' });
            }
        } else {
            // 兼容旧版明文传输（生产环境应禁用）
            phone = req.body.phone;
            code = req.body.code;
            password = req.body.password;
        }

        if (users[phone] != code) {
            res.send({ code: 1, msg: '验证码不正确' });
            return;
        }
        //删除保存的code
        delete users[phone];

        // 读取用户文件
        let usersInfo = await readUsers();
        // 新用户，添加基础信息
        // 先加密密码
        const hashedPassword = bcrypt.hashSync(password, 10);
        const newUser = {
            id: Date.now().toString(), // 生成唯一ID（时间戳）
            phone,
            password: hashedPassword,
            createTime: Date.now(),
            lastLogin: Date.now(),
            nickname: `admin${phone.slice(-4)}`,
            role: 'user',
        };
        usersInfo.push(newUser);
        // 设置 session
        req.session.user = {
            phone: newUser.phone,
            creatTime: newUser.createTime,
            nickname: newUser.nickname,
            role: newUser.role,
        };
        try {
            await writeUsers(usersInfo);
            res.send({ code: 0, data: req.session.user });
        } catch (error) {
            console.error('保存用户文件失败:', error.message);
            res.status(500).send({ code: 1, msg: '服务器内部错误' });
        }
    } catch (error) {
        console.error('注册处理错误:', error.message);
        res.status(500).send({ code: 1, msg: '服务器内部错误' });
    }
});

/*
密码登录：先检查系统用户是否存在，再检验密码
支持加密传输敏感信息
*/
// 支持GET和POST两种方式的用户验证
router.all('/api/check_user', async (req, res) => {
    try {
        // 检查是否是加密数据
        let username, password, rememberMe;

        // 根据请求方法获取参数
        if (req.method === 'GET') {
            // GET请求从query中获取参数
            username = req.query.username;
            password = req.query.password;
            rememberMe = req.query.remember === 'true';
            console.log({ username });
            console.log({ password });
        } else if (req.method === 'POST') {
            if (req.body.encrypted) {
                // 解密数据
                const decryptedData = cryptoUtil.decrypt(req.body.data);
                if (!decryptedData) {
                    return res
                        .status(400)
                        .send({ code: 1, msg: '数据解密失败' });
                }

                try {
                    const parsedData = JSON.parse(decryptedData);
                    username = parsedData.username;
                    password = parsedData.password;
                    rememberMe = parsedData.remember === true;
                } catch (e) {
                    return res
                        .status(400)
                        .send({ code: 1, msg: '解密数据格式错误' });
                }
            } else {
                // 兼容旧版明文传输（生产环境应禁用）
                username = req.body.username;
                password = req.body.password;
                rememberMe = req.body.remember === true;
            }
        }

        // 读取用户文件
        let usersInfo = await readUsers();
        const userIndex = usersInfo.findIndex(u => u.nickname === username);
        if (userIndex !== -1) {
            // 已有用户
            let targetUser = usersInfo[userIndex];
            // 分散出来的一个逻辑，没给密码参数就是简单的检测用户在否
            if (!password) {
                return res.send({ code: 0 });
            }
            // 验证密码
            const compareResult = bcrypt.compareSync(
                password,
                targetUser.password
            );

            if (compareResult) {
                // 短期accessToken，长期refresToken
                const accessToken = jwt.sign(
                    { id: targetUser.id, nickname: targetUser.nickname },
                    config.config.jwtSecretKey,
                    { expiresIn: '5s' } // accessToken 有效期短
                );

                const refreshToken = jwt.sign(
                    { id: targetUser.id },
                    config.config.jwtSecretKey,
                    { expiresIn: rememberMe ? '7d' : '1d' } // refreshToken 更长
                );

                // 设置 HttpOnly Cookie 存储 refreshToken
                res.cookie('refreshToken', refreshToken, {
                    httpOnly: true, // 设置为 HttpOnly，防止前端 JavaScript 访问
                    secure: process.env.NODE_ENV === 'production', // 生产环境下仅在 HTTPS 下有效
                    sameSite: 'strict', // 防止CSRF攻击
                    maxAge: rememberMe
                        ? 7 * 24 * 60 * 60 * 1000
                        : 24 * 60 * 60 * 1000, // 根据 rememberMe 设置有效期
                    path: '/', // Cookie 生效路径
                });

                res.send({
                    code: 0,
                    data: {
                        phone: targetUser.phone,
                        nickname: targetUser.nickname,
                        lastLogin: targetUser.lastLogin,
                        role: targetUser.role,
                        accessToken,
                        // refreshToken不再通过JSON返回，而是存储在HttpOnly Cookie中
                    },
                });
                // console.log('refreshToken发送成功');
                // console.log(accessToken);
                // console.log(refreshToken);
            } else {
                res.send({ code: 1, msg: '密码错误' });
            }
        } else {
            res.send({ code: 1, msg: '系统未注册过该账户' });
        }
    } catch (error) {
        console.error('登录处理错误:', error.message);
        res.status(500).send({ code: 1, msg: '服务器内部错误' });
    }
});

// 刷新token（从HttpOnly Cookie中获取refreshToken，然后签发新的accessToken）
router.post('/api/refresh_token', (req, res) => {
    console.log('刷新token请求');
    // 从HttpOnly Cookie中获取refreshToken
    console.log('req.cookies:', req.cookies);
    const refreshToken = req.cookies.refreshToken;
    console.log('刷新token请求，获取到的refreshToken: ', refreshToken);
    if (!refreshToken)
        return res
            .status(401)
            .send({ code: 1, msg: '缺少 refreshToken，请重新登录' });

    console.log('refreshToken: ', refreshToken);

    try {
        const decoded = jwt.verify(refreshToken, config.config.jwtSecretKey);

        // 重新签发一个新 accessToken
        const newAccessToken = jwt.sign(
            { id: decoded.id },
            config.config.jwtSecretKey,
            { expiresIn: '5s' } // 设置为1小时有效期
        );

        // 可选：如果refreshToken即将过期，也可以在这里更新refreshToken
        // 计算refreshToken的剩余有效期
        const currentTime = Math.floor(Date.now() / 1000);
        const timeRemaining = decoded.exp - currentTime;

        // 如果剩余有效期小于24小时，则更新refreshToken
        if (timeRemaining < 24 * 60 * 60) {
            const newRefreshToken = jwt.sign(
                { id: decoded.id },
                config.config.jwtSecretKey,
                { expiresIn: '7d' } // 新的refreshToken有效期7天
            );

            // 更新HttpOnly Cookie中的refreshToken
            res.cookie('refreshToken', newRefreshToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 7 * 24 * 60 * 60 * 1000,
                path: '/',
            });
        }
        console.log('刷新accessToken');

        res.send({ code: 0, data: { accessToken: newAccessToken } });
    } catch (err) {
        // 如果refreshToken无效或已过期，清除cookie并返回错误
        res.clearCookie('refreshToken');
        res.status(401).send({
            code: 1,
            msg: 'refreshToken 无效或已过期，请重新登录',
        });
    }
});

module.exports = router; // 导出router实例
