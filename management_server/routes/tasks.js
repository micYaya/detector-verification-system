const express = require('express');
const router = express.Router();
const pool = require('../db/db');
// const authenticateToken = require('../middlewares/auth'); // 引入token验证中间件

// // 应用中间件
// router.use(authenticateToken);

// 获取任务信息（支持设备编号过滤）
router.get('/api/tasks', async (req, res) => {
  try {
    const deviceId = req.query.deviceId;
    let sql = 'SELECT * FROM tasks';
    const params = [];
    if (deviceId) {
      sql += ' WHERE deviceId = ?';
      params.push(deviceId);
    }
    const [rows] = await pool.execute(sql, params);
    res.json(rows);
  } catch (error) {
    console.error('获取任务信息失败', error);
    res.status(500).json({ error: '获取任务信息失败' });
  }
});

// 创建任务接口
router.post('/api/tasks', async (req, res) => {
  try {
    console.log(req.body);
    const { deviceId, startTime, endTime, status } = req.body;
    const [result] = await pool.execute(
      'INSERT INTO tasks (deviceId, startTime, endTime, status) VALUES (?, ?, ?, ?)',
      [deviceId, startTime || null, endTime || null, status]
    );
    const taskId = result.insertId;
    console.log('taskId:', taskId);
    res.json({ id: taskId, deviceId, startTime, endTime, status });
  } catch (error) {
    console.error('创建任务失败', error);
    res.status(500).json({ error: '创建任务失败' });
  }
});

// 更新任务接口
router.put('/api/tasks/:id', async (req, res) => {
  try {
    const taskId = req.params.id;
    console.log(req.body);
    const { deviceId, startTime, endTime, status } = req.body;
    
    await pool.execute(
      'UPDATE tasks SET deviceId = ?, startTime = ?, endTime = ?, status = ? WHERE id = ?',
      [deviceId, startTime || null, endTime || null, status, taskId]
    );
    res.json({ message: '任务更新成功' });
  } catch (error) {
    console.error('更新任务失败', error);
    res.status(500).json({ error: '更新任务失败' });
  }
});

// 删除任务信息
router.delete('/api/tasks/:id', async (req, res) => {
    const id = req.params.id;
    try {
        await pool.execute('DELETE FROM tasks WHERE id = ?', [id]);
        res.json({ message: '任务信息删除成功' });
    } catch (error) {
        console.error('删除任务信息失败', error);
        res.status(500).json({ error: '删除任务信息失败' });
    }
});

// 获取任务里的实验项目数量
router.get('/api/tasks/with-item-count', async (req, res) => {
  try {
    const [rows] = await pool.execute(`
      SELECT 
        tasks.id, 
        tasks.deviceId, 
        tasks.startTime,
        tasks.endTime, 
        tasks.status,
        COUNT(inspection_items.item_id) as item_count
      FROM tasks
      LEFT JOIN inspection_items ON tasks.id = inspection_items.task_id
      GROUP BY tasks.id, tasks.deviceId, tasks.startTime, tasks.endTime, tasks.status
    `);
    res.json(rows);
  } catch (error) {
    console.error('获取任务及实验项目数量失败', error);
    res.status(500).json({ error: '获取任务及实验项目数量失败' });
  }
});

module.exports = router;