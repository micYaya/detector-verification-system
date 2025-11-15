// stores/index.js
import { defineStore } from 'pinia';

export const useLoginStore = defineStore('login', {
    state: () => ({
        userInfo: {
            username: null, // 用户名
            role: 'user', // 角色
        },
        phoneNumber: null, // 电话号码
    }),
    actions: {
        setUserInfo(username, role) {
            this.userInfo = {
                username,
                role,
            };
        },
        setPhoneNumber(phone) {
            this.phoneNumber = phone; // 设置电话号码
        },
        logout() {
            this.userInfo = {
                username: null,
                role: 'user',
            };
            localStorage.removeItem('user');
            this.phoneNumber = null;
            localStorage.removeItem('accessToken');
            localStorage.removeItem('rememberMe');
            sessionStorage.removeItem('accessToken');
            // 刷新令牌由后端HttpOnly Cookie管理，无需前端清理
        },
        // 页面刷新时在本地存储中找用户信息
        initUserInfo() {
            const userInfo = localStorage.getItem('user');
            if (userInfo) {
                this.userInfo = JSON.parse(userInfo);
                console.log('状态管理里的userinfo：', this.userInfo);
            }
        },
        setLogin(userinfo = null) {
            if (userinfo) {
                this.userInfo = userinfo;
                localStorage.setItem('user', JSON.stringify(userinfo));
            }
        },
    },
    getters: {
        getUserInfo: state => state.userInfo,
        isLoggedIn: state => !!state.userInfo.username,
        getPhoneNumber: state => state.phoneNumber,
        getUserRole: state => state.userInfo.role,
    },
});
