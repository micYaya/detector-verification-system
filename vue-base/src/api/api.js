// api.js
import axios from 'axios';
import { jwtDecode } from 'jwt-decode';
import { useLoginStore } from '@/store/index';
import router from '@/router';
import { ElMessage } from 'element-plus';

const api = axios.create({
    baseURL: import.meta.env.VITE_API_BASE_URL,
    timeout: 30000,
    withCredentials: true,
});

let isRefreshing = false;
let refreshSubscribers = [];

// 基于 HttpOnly Cookie 的刷新，不再从本地读取 refreshToken
const refreshAccessToken = async rememberMe => {
    try {
        const res = await axios.post(
            `${api.defaults.baseURL}/api/refresh_token`,
            {},
            { withCredentials: true }
        );
        const newAccessToken = res.data.data.accessToken;
        if (rememberMe) {
            localStorage.setItem('accessToken', newAccessToken);
        } else {
            sessionStorage.setItem('accessToken', newAccessToken);
        }
        return newAccessToken;
    } catch (error) {
        return null;
    }
};

// 请求拦截器
api.interceptors.request.use(async config => {
    console.log('拦截器进入了');
    // console.log('请求拦截器 - 配置:', config);
    if (config.url && config.url.endsWith('/api/refresh_token')) {
        return config;
    }
    const accessToken =
        localStorage.getItem('accessToken') ||
        sessionStorage.getItem('accessToken');
    const rememberMe = localStorage.getItem('rememberMe') === 'true';
    const loginStore = useLoginStore();
    const userInfo = loginStore.getUserInfo;
    // console.log('请求拦截器的userInfo：', userInfo);
    // console.log('rememberMe: ', rememberMe);
    // console.log('accessToken: ', accessToken);
    // console.log('refreshToken: ', refreshToken);
    if (accessToken) {
        const decoded = jwtDecode(accessToken);
        console.log({ decoded });
        // console.log('token 到期时间:', decoded.exp * 1000, '当前时间:', Date.now());
        const now = Date.now() / 1000;
        console.log(isRefreshing);
        if (decoded.exp < now && !isRefreshing) {
            console.log('accessToken 已过期，尝试刷新');
            isRefreshing = true;
            const newAccessToken = await refreshAccessToken(rememberMe);
            if (newAccessToken) {
                localStorage.setItem('user', JSON.stringify(userInfo));
                config.headers.Authorization = `Bearer ${newAccessToken}`;
                // 执行队列里的请求
                refreshSubscribers.forEach(({ resolve }) =>
                    resolve(newAccessToken)
                );
                refreshSubscribers = [];
                isRefreshing = false;
                return config;
            } else {
                isRefreshing = false;
                console.error('Token 刷新失败，准备跳转登录页面');
                loginStore.logout();
                // window.location.href = '/login';
                // 刷新失败，拒绝队列中的请求，防止悬挂
                refreshSubscribers.forEach(({ reject }) =>
                    reject(new Error('刷新 Token 失败'))
                );
                refreshSubscribers = [];
                return Promise.reject(new Error('刷新 Token 失败'));
            }
        } else if (decoded.exp < now && isRefreshing) {
            // 如果正在刷新token，就将请求放入队列
            return new Promise((resolve, reject) => {
                refreshSubscribers.push({
                    resolve: newAccessToken => {
                        config.headers.Authorization = `Bearer ${newAccessToken}`;
                        resolve(config);
                    },
                    reject,
                });
            });
        }
        config.headers.Authorization = `Bearer ${accessToken}`;
    }
    return config;
});

// 响应拦截器
api.interceptors.response.use(
    response => response,
    async error => {
        const originalRequest = error.config;
        const rememberMe = localStorage.getItem('rememberMe') === 'true';
        const loginStore = useLoginStore();
        const redirect = router.currentRoute.value.fullPath;

        if (
            error.response &&
            error.response.status === 401 &&
            !originalRequest._retry
        ) {
            originalRequest._retry = true;
            const newAccessToken = await refreshAccessToken(rememberMe);
            if (newAccessToken) {
                originalRequest.headers.Authorization = `Bearer ${newAccessToken}`;
                return api(originalRequest);
            } else {
                if (rememberMe) {
                    localStorage.removeItem('accessToken');
                    localStorage.removeItem('user');
                } else {
                    sessionStorage.removeItem('accessToken');
                    localStorage.removeItem('user');
                }
                loginStore.logout();
                ElMessage.error('登录状态已失效，请重新登录');
                router.push({ path: '/login', query: { redirect } });
            }
        }
        if (error.response && error.response.status === 403) {
            ElMessage.error('无权限访问');
        } else if (error.response && error.response.status >= 500) {
            ElMessage.error('服务器错误');
        } else if (!error.response) {
            ElMessage.error('网络错误');
        }
        return Promise.reject(error);
    }
);

export default api;
