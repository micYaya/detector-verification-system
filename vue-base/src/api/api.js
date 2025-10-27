// api.js
import axios from 'axios';
import { jwtDecode } from 'jwt-decode';
import { useLoginStore } from '@/store/index';

const api = axios.create({
  baseURL: 'http://127.0.0.1:3000', // 后端服务器地址
  // baseURL: 'http://192.168.2.119:3000', // 局域网内的 IP 地址
  timeout: 30000,
  withCredentials: true // 允许携带跨域请求的 Cookie
});

let isRefreshing = false;
let refreshSubscribers = [];

const refreshAccessToken = async (refreshToken, rememberMe) => {
  try {
    // console.log('开始请求更换accessToken');
    const config = {
      headers: {
        Authorization: `Bearer ${refreshToken}`,
      },
    };
    const res = await axios.post(
      'http://127.0.0.1:3000/api/refresh_token',
      {},
      config,
    );
    // console.log('刷新请求已发送');
    const newAccessToken = res.data.data.accessToken;
    // console.log('更换accessToken');
    if (rememberMe) {
      localStorage.setItem('accessToken', newAccessToken);
      // console.log('已更新本地存储的accessToken');
    } else {
      sessionStorage.setItem('accessToken', newAccessToken);
      // console.log('已更新会话的accessToken');
    }
    return newAccessToken;
  } catch (error) {
    return null;
  }
};

// 请求拦截器
api.interceptors.request.use(async (config) => {
  console.log('拦截器进入了');
  // console.log('请求拦截器 - 配置:', config);
  const accessToken =
    localStorage.getItem('accessToken') ||
    sessionStorage.getItem('accessToken');
  const refreshToken =
    localStorage.getItem('refreshToken') ||
    sessionStorage.getItem('refreshToken');
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
    // console.log(isRefreshing);
    if (decoded.exp < now && !isRefreshing) {
      // console.log('accessToken 已过期，尝试刷新');
      isRefreshing = true;
      const newAccessToken = await refreshAccessToken(refreshToken, rememberMe);
      if (newAccessToken) {
        localStorage.setItem('user', JSON.stringify(userInfo));
        config.headers.Authorization = `Bearer ${newAccessToken}`;
        // 执行队列里的请求
        refreshSubscribers.forEach((callback) => callback(newAccessToken));
        refreshSubscribers = [];
        isRefreshing = false;
        return config;
      } else {
        isRefreshing = false;
        console.error('Token 刷新失败，准备跳转登录页面');
        loginStore.logout();
        // window.location.href = '/login';
        return Promise.reject(new Error('刷新 Token 失败'));
      }
    } else if (decoded.exp < now && isRefreshing) {
      // 如果正在刷新token，就将请求放入队列
      return new Promise((resolve) => {
        refreshSubscribers.push((newAccessToken) => {
          config.headers.Authorization = `Bearer ${newAccessToken}`;
          resolve(config);
        });
      });
    }
    config.headers.Authorization = `Bearer ${accessToken}`;
  }
  return config;
});

// 响应拦截器
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    const rememberMe = localStorage.getItem('rememberMe') === 'true';
    const loginStore = useLoginStore();

    if (
      error.response &&
      error.response.status === 401 &&
      !originalRequest._retry
    ) {
      originalRequest._retry = true;
      const refreshToken =
        localStorage.getItem('refreshToken') ||
        sessionStorage.getItem('refreshToken');
      const newAccessToken = await refreshAccessToken(refreshToken, rememberMe);
      if (newAccessToken) {
        originalRequest.headers.Authorization = `Bearer ${newAccessToken}`;
        return api(originalRequest);
      } else {
        if (rememberMe) {
          localStorage.removeItem('accessToken');
          localStorage.removeItem('refreshToken');
          localStorage.removeItem('user');
        } else {
          sessionStorage.removeItem('accessToken');
          sessionStorage.removeItem('refreshToken');
          localStorage.removeItem('user');
        }
        loginStore.logout();
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  },
);

export default api;
