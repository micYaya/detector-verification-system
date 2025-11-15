const express = require('express');
const router = express.Router();
const pool = require('../db/db');
// const authenticateToken = require('../middlewares/auth'); // 引入token验证中间件

// // 应用中间件
// router.use(authenticateToken);

// 获取所有结果信息
router.get('/api/results', async (req, res) => {
    try {
        const deviceId = req.query.deviceId;
        let sql = 'SELECT * FROM results';
        const params = [];
        if (deviceId) {
            sql += ' WHERE deviceId = ?';
            params.push(deviceId);
        }
        const [rows] = await pool.execute(sql, params);
        res.json(rows);
    } catch (error) {
        console.error('获取结果列表失败', error);
        res.status(500).json({ error: '获取结果列表失败' });
    }
});

// 添加结果信息
router.post('/api/results', async (req, res) => {
    const {
        deviceId,
        twoP,
        tanValue,
        measuredId,
        temperature,
        humidity,
        testDate,
        rate,
        fa,
        fb,
        fc,
        da,
        db,
        dc,
        dUa,
        dUb,
        dUc,
        Upta,
        Uptb,
        Uptc,
        Uyba,
        Uybb,
        Uybc,
        res1,
        res2,
        res3,
        res4,
    } = req.body;
    // 转换日期格式
    if (testDate) {
        req.body.testDate = new Date(testDate).toISOString().split('T')[0];
    }
    // 将undefined转换为null
    const params = [
        deviceId,
        twoP,
        tanValue,
        measuredId,
        temperature,
        humidity,
        testDate,
        rate,
        fa,
        fb,
        fc,
        da,
        db,
        dc,
        dUa,
        dUb,
        dUc,
        Upta,
        Uptb,
        Uptc,
        Uyba,
        Uybb,
        Uybc,
        res1,
        res2,
        res3,
        res4,
    ].map(param => (param === undefined ? null : param));

    try {
        const [result] = await pool.execute(
            `INSERT INTO results 
        (deviceId, twoP, tanValue, measuredId, 
         temperature, humidity, testDate, rate,
         fa, fb, fc, da, db, dc,
         dUa, dUb, dUc, Upta, Uptb, Uptc,
         Uyba, Uybb, Uybc, res1, res2, res3, res4) 
      VALUES 
        (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
            params
        );
        res.status(201).json({ id: result.insertId, ...req.body });
    } catch (error) {
        console.error('数据库插入错误详情：', error);
        res.status(500).json({ error: '添加结果失败' });
    }
});

// 更新结果信息
router.put('/api/results/:id', async (req, res) => {
    const id = req.params.id;
    const {
        deviceId,
        twoP,
        tanValue,
        measuredId,
        temperature,
        humidity,
        testDate,
        rate,
        fa,
        fb,
        fc,
        da,
        db,
        dc,
        dUa,
        dUb,
        dUc,
        Upta,
        Uptb,
        Uptc,
        Uyba,
        Uybb,
        Uybc,
        res1,
        res2,
        res3,
        res4,
    } = req.body;
    console.log(req.body);
    console.log('twoP 类型:', typeof twoP);
    try {
        await pool.execute(
            `UPDATE results 
       SET 
         deviceId = ?, twoP = ?, tanValue = ?, measuredId = ?, 
         temperature = ?, humidity = ?, testDate = ?, rate = ?,
         fa = ?, fb = ?, fc = ?, da = ?, db = ?, dc = ?,
         dUa = ?, dUb = ?, dUc = ?, Upta = ?, Uptb = ?, Uptc = ?,
         Uyba = ?, Uybb = ?, Uybc = ?, res1 = ?, res2 = ?, res3 = ?, res4 = ?
       WHERE resultId = ?`,
            [
                deviceId,
                twoP,
                tanValue,
                measuredId,
                temperature,
                humidity,
                testDate,
                rate,
                fa,
                fb,
                fc,
                da,
                db,
                dc,
                dUa,
                dUb,
                dUc,
                Upta,
                Uptb,
                Uptc,
                Uyba,
                Uybb,
                Uybc,
                res1,
                res2,
                res3,
                res4,
                id,
            ]
        );
        res.json({ id, ...req.body });
    } catch (error) {
        console.error('更新结果失败', error);
        res.status(500).json({ error: '更新结果失败' });
    }
});

// 删除结果信息
router.delete('/api/results/:id', async (req, res) => {
    const id = req.params.id;
    try {
        await pool.execute('DELETE FROM results WHERE resultId = ?', [id]);
        res.json({ message: '结果删除成功' });
    } catch (error) {
        console.error('删除结果失败', error);
        res.status(500).json({ error: '删除结果失败' });
    }
});

router.get('/api/results/:id', async (req, res) => {
    const id = req.params.id;
    try {
        const [rows] = await pool.execute(
            'SELECT * FROM results WHERE resultId = ?',
            [id]
        );
        if (rows.length === 0) {
            return res.status(404).json({ error: '结果不存在' });
        }
        const result = rows[0];
        console.log('tanValue 类型:', typeof result.tanValue);
        res.json(result);
    } catch (error) {
        console.error('获取结果详情失败', error);
        res.status(500).json({ error: '获取结果详情失败' });
    }
});

module.exports = router;
