import api from './api.js';
export default function ajax(url = '', data = {}, type = 'GET') {
    return new Promise(function (resolve, reject) {
        let promise;
        console.log('data: ', data);
        if (type === 'GET') {
            // 准备url query 参数数据
            let dataStr = ''; //数据拼接字符串
            Object.keys(data).forEach(key => {
                dataStr += key + '=' + data[key] + '&';
            });
            if (dataStr !== '') {
                dataStr = dataStr.substring(0, dataStr.lastIndexOf('&'));
                url = url + '?' + dataStr;
            }
            console.log('url: ', url);
            // 发送get 请求
            promise = api.get(url);
        } else {
            // 发送post 请求
            console.log('post url: ', url);
            promise = api.post(url, data);
        }
        promise
            .then(response => {
                resolve(response.data);
            })
            .catch(error => {
                reject(error);
            });
    });
}
