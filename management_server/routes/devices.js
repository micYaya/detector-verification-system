const express = require('express');
const router = express.Router();
const pool = require('../db/db'); // 引入数据库连接池
// const authenticateToken = require('../middlewares/auth'); // 引入token验证中间件

// // 应用中间件
// router.use(authenticateToken);

// 获取所有设备信息
router.get('/api/devices', async (req, res) => {
    try {
        const [rows] = await pool.execute('SELECT * FROM devices');
        res.json(rows);
    } catch (error) {
        console.error('获取设备信息失败', error);
        res.status(500).json({ error: '获取设备信息失败' });
    }
});

// 根据deviceId获取单个设备的信息
router.get('/api/devices/:deviceId', async (req, res) => {
    const deviceId = req.params.deviceId;
    try {
        // 使用数据库连接池pool执行SQL查询
        const [rows] = await pool.execute(
            'SELECT * FROM devices WHERE deviceId = ?',
            [deviceId]
        );
        if (rows.length === 0) {
            console.log('该设备编号不存在');
            return res.json({ exist: 0, error: '该设备编号不存在' });
        }
        res.json(rows[0]);
    } catch (error) {
        console.error('获取此Id对应的设备信息失败', error);
        res.json({ error: '获取此Id对应的设备信息失败' });
    }
});

// 添加设备信息
router.post('/api/devices', async (req, res) => {
    const {
        deviceId,
        deviceName,
        deviceModel,
        manufactureDate,
        inspectionDate,
        manufacturer,
        productionPlace,
        deviceStatus,
    } = req.body;
    try {
        const [result] = await pool.execute(
            'INSERT INTO devices (deviceId, deviceName, deviceModel, manufactureDate, inspectionDate, manufacturer, productionPlace, deviceStatus) VALUES (?,?,?,?,?,?,?,?)',
            [
                deviceId,
                deviceName,
                deviceModel,
                manufactureDate,
                inspectionDate,
                manufacturer,
                productionPlace,
                deviceStatus,
            ]
        );
        res.status(201).json({
            id: result.insertId,
            deviceId,
            deviceName,
            deviceModel,
            manufactureDate,
            inspectionDate,
            manufacturer,
            productionPlace,
            deviceStatus,
        });
    } catch (error) {
        console.error('数据库插入错误详情：', error);
        res.status(500).json({ error: '添加设备信息失败' });
    }
});

// 更新设备信息
router.put('/api/devices/:id', async (req, res) => {
    const id = req.params.id;
    const {
        deviceId,
        deviceName,
        deviceModel,
        manufactureDate,
        inspectionDate,
        manufacturer,
        productionPlace,
        deviceStatus,
    } = req.body;
    try {
        await pool.execute(
            'UPDATE devices SET deviceId = ?, deviceName = ?, deviceModel = ?, manufactureDate = ?, inspectionDate = ?, manufacturer = ?, productionPlace = ?, deviceStatus = ? WHERE id = ?',
            [
                deviceId,
                deviceName,
                deviceModel,
                manufactureDate,
                inspectionDate,
                manufacturer,
                productionPlace,
                deviceStatus,
                id,
            ]
        );
        res.json({
            id,
            deviceId,
            deviceName,
            deviceModel,
            manufactureDate,
            inspectionDate,
            manufacturer,
            productionPlace,
            deviceStatus,
        });
    } catch (error) {
        console.error('更新设备信息失败', error);
        res.status(500).json({ error: '更新设备信息失败' });
    }
});

// 更新设备检测状态
router.put('/api/devices/:id/status', async (req, res) => {
    const id = req.params.id;
    const { deviceStatus } = req.body;

    try {
        await pool.execute(
            'UPDATE devices SET deviceStatus = ? WHERE deviceId = ?',
            [deviceStatus, id]
        );
        res.json({ id, deviceStatus });
    } catch (error) {
        console.error('更新设备检测状态失败', error);
        res.status(500).json({ error: '更新设备检测状态失败' });
    }
});

// 删除设备信息
router.delete('/api/devices/:id', async (req, res) => {
    const id = req.params.id;
    try {
        await pool.execute('DELETE FROM devices WHERE id = ?', [id]);
        res.json({ message: '设备信息删除成功' });
    } catch (error) {
        console.error('删除设备信息失败', error);
        res.status(500).json({ error: '删除设备信息失败' });
    }
});

module.exports = router;
