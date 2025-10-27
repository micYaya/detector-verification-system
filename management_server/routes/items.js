const express = require('express');
const router = express.Router();
const pool = require('../db/db');
// const authenticateToken = require('../middlewares/auth'); // 引入token验证中间件

// // 应用中间件
// router.use(authenticateToken);

// 获取所有检测项目信息
router.get('/api/inspection_items', async (req, res) => {
    try {
        const [rows] = await pool.execute('SELECT * FROM inspection_items');
        res.json(rows);
    } catch (error) {
        console.error('获取检测项目信息失败', error);
        res.status(500).json({ error: '获取检测项目信息失败' });
    }
});

// 添加检测项目信息
router.post('/api/inspection_items', async (req, res) => {
    const { project, gear, percentage, data_lower_limit, data_upper_limit, measured_data, task_id } = req.body;
    try {
        console.log('后端接收到的添加检测项目数据：', { project, gear, percentage, data_lower_limit, data_upper_limit, measured_data, task_id });
        const [result] = await pool.execute(
            'INSERT INTO inspection_items (project, gear, percentage, data_lower_limit, data_upper_limit, measured_data, task_id) VALUES (?,?,?,?,?,?,?)',
            [project, gear, percentage, data_lower_limit, data_upper_limit, measured_data, task_id]
        );
        res.status(201).json({ id: result.insertId, project, gear, percentage, data_lower_limit, data_upper_limit, measured_data, task_id });
    } catch (error) {
        console.error('数据库插入检测项目错误详情：', error);
        res.status(500).json({ error: '添加检测项目信息失败' });
    }
});

// 更新检测项目信息
router.put('/api/inspection_items/:id', async (req, res) => {
    const id = req.params.id;
    const { project, gear, percentage, data_lower_limit, data_upper_limit, measured_data, task_id } = req.body;
    try {
        await pool.execute(
            'UPDATE inspection_items SET project = ?, gear = ?, percentage = ?, data_lower_limit = ?, data_upper_limit = ?, measured_data = ?, task_id = ? WHERE item_id = ?',
            [project, gear, percentage, data_lower_limit, data_upper_limit, measured_data, task_id, id]
        );
        res.json({ id, project, gear, percentage, data_lower_limit, data_upper_limit, measured_data, task_id });
    } catch (error) {
        console.error('更新检测项目信息失败', error);
        res.status(500).json({ error: '更新检测项目信息失败' });
    }
});

// 删除检测项目信息
router.delete('/api/inspection_items/:id', async (req, res) => {
    const id = req.params.id;
    try {
        await pool.execute('DELETE FROM inspection_items WHERE item_id = ?', [id]);
        res.json({ message: '检测项目信息删除成功' });
    } catch (error) {
        console.error('删除检测项目信息失败', error);
        res.status(500).json({ error: '删除检测项目信息失败' });
    }
});

module.exports = router;