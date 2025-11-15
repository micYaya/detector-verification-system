require('dotenv').config();
const OpenAI = require('openai');

// API相关配置
const API_KEY = process.env.API_KEY;
const ENDPOINT_ID = process.env.ENDPOINT_ID;

// 初始化 OpenAI 客户端
const openai = new OpenAI({
    apiKey: API_KEY,
    baseURL: 'https://ark.cn-beijing.volces.com/api/v3',
});

// 调用豆包大模型 API
async function callDoubaoAPI() {
    try {
        let index = Math.floor(Math.random() * 200 + 1);
        console.log({ index });
        // 两张图片的 URL
        // const randomImageUrl = 'https://a43c-240e-45d-ce60-9575-d878-c1d5-25cd-aa4f.ngrok-free.app/';
        // const templateImageUrl = 'https://a43c-240e-45d-ce60-9575-d878-c1d5-25cd-aa4f.ngrok-free.app/template_image.jpg';
        const randomImageUrl = `https://images-yayamic.tos-cn-beijing.volces.com/images/${index}.jpg`;
        const templateImageUrl =
            'https://images-yayamic.tos-cn-beijing.volces.com/template_image.jpg';
        const data = {
            messages: [
                {
                    role: 'user',
                    content: [
                        {
                            type: 'text',
                            text: `第一张图片是模板图片，红色方框是旁边黄色字体字段所对应的数据内容，现在给我第二张图片的所有字段对应的数据，请解析第二张图片， 包含字段：
                            twoP, tanValue, measuredId, temperature, humidity, testDate,
                            fa, fb, fc, da, db, dc, dUa, dUb, dUc,
                            Upta, Uptb, Uptc, Uyba, Uybb, Uybc,
                            rate, res1, res2, res3, res4
                        所返回内容格式如下（注意 testDate 对应的数据里年月日之间需要用英文的“-”隔开）：
                        {
                              twoP: '78.6',
                              tanValue: '-1.2866',
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
                            }`,
                        },
                        {
                            type: 'image_url',
                            image_url: {
                                url: templateImageUrl,
                            },
                        },
                        {
                            type: 'image_url',
                            image_url: {
                                url: randomImageUrl,
                            },
                        },
                    ],
                },
            ],
            model: ENDPOINT_ID,
        };

        const completion = await openai.chat.completions.create(data);
        const responseContent = completion.choices[0]?.message?.content;
        console.log('大模型回复内容:', responseContent);
        console.log(randomImageUrl);
        return responseContent;
    } catch (error) {
        if (error.code === 'ECONNREFUSED') {
            console.error('无法连接到随机图片服务，请检查服务是否启动。');
        } else {
            console.error('调用豆包大模型失败:', error);
        }
        throw error;
    }
}

module.exports = { callDoubaoAPI };
