/**
 * API请求适配器
 * 支持refreshToken和敏感信息加密传输
 */
import axios from 'axios';
import { encrypt } from './crypto';

// 创建axios实例
const service = axios.create({
    baseURL: import.meta.env.VITE_API_BASE_URL,
    timeout: 15000,
    withCredentials: true, // 允许跨域请求携带凭证（Cookie）
});

// 是否启用API加密
const enableEncryption = import.meta.env.VITE_ENABLE_API_ENCRYPTION === 'true';

// 请求拦截器
service.interceptors.request.use(
    config => {
        // 从localStorage获取accessToken
        const token = localStorage.getItem('accessToken');
        if (token) {
            config.headers['Authorization'] = `Bearer ${token}`;
        }

        return config;
    },
    error => {
        console.error('请求错误:', error);
        return Promise.reject(error);
    }
);

// 响应拦截器
service.interceptors.response.use(
    response => {
        return response.data;
    },
    async error => {
        if (error.response && error.response.status === 401) {
            // Token过期，尝试刷新
            try {
                // 调用刷新token接口，refreshToken会自动从Cookie中获取
                const res = await axios.post(
                    `${import.meta.env.VITE_API_BASE_URL}/api/refresh_token`,
                    {},
                    { withCredentials: true }
                );

                if (res.data.code === 0) {
                    // 更新localStorage中的accessToken
                    localStorage.setItem(
                        'accessToken',
                        res.data.data.accessToken
                    );

                    // 重新发起之前失败的请求
                    const config = error.config;
                    config.headers['Authorization'] =
                        `Bearer ${res.data.data.accessToken}`;
                    return service(config);
                } else {
                    // 刷新失败，需要重新登录
                    localStorage.removeItem('accessToken');
                    window.location.href = '/login';
                }
            } catch (refreshError) {
                // 刷新token失败，清除token并跳转到登录页
                localStorage.removeItem('accessToken');
                window.location.href = '/login';
                return Promise.reject(refreshError);
            }
        }
        return Promise.reject(error);
    }
);

/**
 * 加密请求数据（用于敏感信息传输）
 * @param {Object} data - 请求数据
 * @returns {Object} - 加密后的数据
 */
export function encryptRequestData(data) {
    if (!enableEncryption) return data;

    return {
        encrypted: true,
        data: encrypt(data),
    };
}

/**
 * 登录请求
 * @param {Object} loginData - 登录数据
 * @returns {Promise} - 请求Promise
 */
export function login(loginData) {
    const data = enableEncryption ? encryptRequestData(loginData) : loginData;
    return service.post('/api/check_user', data);
}

/**
 * 注册请求
 * @param {Object} registerData - 注册数据
 * @returns {Promise} - 请求Promise
 */
export function register(registerData) {
    const data = enableEncryption
        ? encryptRequestData(registerData)
        : registerData;
    return service.post('/api/register', data);
}

export default service;
