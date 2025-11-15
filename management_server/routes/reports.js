const express = require('express');
const router = express.Router();
const pool = require('../db/db');
// const authenticateToken = require('../middlewares/auth'); // 引入token验证中间件

// // 应用中间件
// router.use(authenticateToken);

// 获取设备报表信息（包含关联数据）
router.get('/api/reports/:deviceId', async (req, res) => {
    try {
        const deviceId = req.params.deviceId;

        // 1. 获取设备信息
        const [deviceRows] = await pool.execute(
            'SELECT * FROM devices WHERE deviceId = ?',
            [deviceId]
        );
        if (deviceRows.length === 0) {
            return res.status(404).json({ error: '设备不存在' });
        }
        const deviceInfo = deviceRows[0];

        // 2. 获取任务信息（每个设备对应一个任务）
        const [taskRows] = await pool.execute(
            'SELECT * FROM tasks WHERE deviceId = ?',
            [deviceId]
        );
        const taskInfo = taskRows[0];

        // 3. 获取实验项目信息
        const [itemRows] = await pool.execute(
            'SELECT * FROM inspection_items WHERE task_id = ?',
            [taskInfo.id]
        );
        const itemList = itemRows;

        // 4. 获取每个实验项目的结果信息，根据设备编号查询
        const [resultRows] = await pool.execute(
            'SELECT * FROM results WHERE deviceId = ?',
            [deviceId]
        );
        const resultList = resultRows;

        const reportData = {
            deviceInfo,
            taskInfo,
            itemList,
            resultList,
        };

        res.json(reportData);
    } catch (error) {
        console.error('获取报表数据失败:', error);
        res.status(500).json({ error: '获取报表数据失败' });
    }
});

module.exports = router;
