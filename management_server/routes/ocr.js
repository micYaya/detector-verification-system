const express = require('express');
const router = express.Router();
const { callDoubaoAPI } = require('../utils/process.js'); // 引入 OCR 处理函数
const pool = require('../db/db'); // 引入数据库连接池
// const authenticateToken = require('../middlewares/auth'); // 引入token验证中间件

// // 应用中间件
// router.use(authenticateToken);

// OCR 处理接口
router.post('/api/perform-ocr', async (req, res) => {
  console.log('perform');
  try {
    const deviceId = parseInt(req.body.deviceId); // 初始化时完成转换，不后续赋值
    console.log('2');
    // const { matchedData, imageUrl } = await callDoubaoAPI();

    const matchedData = await callDoubaoAPI();
    let imageUrl = '';
    // console.log('imageUrl:', imageUrl);
    console.log('matchedData', matchedData);
    console.log(JSON.parse(matchedData));
    const testData = {
      'twoP': '78.6',
      'tanValue': '-1.2866',
      measuredId: 55894688,
      temperature: '20.3',
      humidity: '80.3',
      testDate: "2023-11-19",
      fa: '0.6775',
      fb: '0.8060',
      fc: '0.6180',
      da: '-0.601',
      db: '-0.401',
      dc: '-0.207',
      dUa: '0.6961',
      dUb: '0.3159',
      dUc: '0.0470',
      Upta: '69.555',
      Uptb: '71.317',
      Uptc: '40.714',
      Uyba: '12.283',
      Uybb: '55.243',
      Uybc: '1.792',
      rate: '0.510',
      res1: '1.792',
      res2: '1.792',
      res3: '0.510',
      res4: '0.510'
    };
    // 将数据保存到 results 表
    const { 
      twoP, tanValue, measuredId, 
      temperature, humidity, testDate, rate,
      fa, fb, fc, da, db, dc,
      dUa, dUb, dUc, Upta, Uptb, Uptc,
      Uyba, Uybb, Uybc, res1, res2, res3, res4 
    } = JSON.parse(matchedData);
    // } = testData;

    const params = [
      deviceId, twoP, tanValue, measuredId, 
      temperature, humidity, testDate, rate,
      fa, fb, fc, da, db, dc,
      dUa, dUb, dUc, Upta, Uptb, Uptc,
      Uyba, Uybb, Uybc, res1, res2, res3, res4,
      imageUrl
    ].map(param => param === undefined ? null : param);

    console.log('插入参数数量:', params.length, '参数:', params);
    const [result] = await pool.execute(
      `INSERT INTO results 
        (deviceId, twoP, tanValue, measuredId, 
         temperature, humidity, testDate, rate,
         fa, fb, fc, da, db, dc,
         dUa, dUb, dUc, Upta, Uptb, Uptc,
         Uyba, Uybb, Uybc, res1, res2, res3, res4, imageUrl) 
      VALUES 
        (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      params
    );
    
    res.status(201).json({ id: result.insertId, ...matchedData, imageUrl });
    // res.status(201).json({ id: result.insertId, ...testData, imageUrl });
  } catch (error) {
    console.error('OCR 处理及数据保存失败:', error);
    res.status(500).json({ error: 'OCR 处理及数据保存失败' });
  }
});

module.exports = router;