import { createRouter, createWebHashHistory, createWebHistory } from 'vue-router';  // createWebHistory
import { ElMessageBox } from 'element-plus';
import { useLoginStore } from '@/store/index';
import api from '@/api/api';
import { jwtDecode } from 'jwt-decode'; // 解析JWT令牌
// 从 @/views/XXX 路径导入XXX组件。@指向src目录
import Login from '@/views/Login/Login.vue';
import Home from '@/views/Home/Index.vue';
import ReportList from '@/views/Report/ReportList.vue';
import UserManage from '@/views/UserManage/UserManage.vue';

// 存储路由配置信息
const routes = [
  {
    path: '/',
    redirect: '/login',
  },
  {
    path: '/login',
    name: 'login',
    component: Login,
  },
  {
    path: '/forget-password',
    name: 'forget-password',
    component: () => import('@/views/Login/ForgetPassword.vue'),
  },
  {
    path: '/register',
    name: 'register',
    component: () => import('@/views/Login/Register.vue'),
  },
  {
    path: '/home',
    name: 'home',
    component: Home,
    meta: { requiresAuth: true },
    children: [
      {
        path: '',
        name: 'origin',
        component: () => import('@/views/Home/origin.vue'),
      },
      {
        path: 'device-info',
        name: 'device-info',
        component: () => import('@/views/Device/DeviceList.vue'),
      },
      {
        path: 'task-info',
        name: 'task-info',
        component: () => import('@/views/Task/TaskList.vue'),
      },
      {
        path: 'item-info/:taskId',
        name: 'item-info',
        component: () => import('@/views/Task/Items/ItemList.vue'),
      },
      {
        path: 'result-info',
        name: 'result-info',
        component: () => import('@/views/Result/ResultList.vue'),
      },
      {
        path: 'report-info',
        name: 'report-info',
        component: ReportList,
      },
      {
        path: 'statistic-info',
        name: 'statistic-info',
        component: () => import('@/views/Statistic/Statistic.vue'),
      },
    ],
  },
];

const user = JSON.parse(localStorage.getItem('user'));
if (user?.role === 'admin') {
  const adminChildRoute = {
    path: 'user-mange',
    name: 'home-user-mange',
    component: UserManage,
    meta: { requiresAuth: true, requiresAdmin: true },
  };
  const homeRoute = routes.find((r) => r.name === 'home');
  if (homeRoute && homeRoute.children) {
    homeRoute.children.push(adminChildRoute);
  }
}

// // 定义超级管理员专用子路由
// const adminChildRoute = {
//   path: 'user-mange',
//   name: 'home-user-mange',
//   // component: () => import('@/views/UserManage/UserManage.vue'),
//   component: UserManage,
//   meta: { requiresAuth: true, requiresAdmin: true },
// };

const router = createRouter({
  history: createWebHistory(),
  // history: createWebHashHistory(),
  routes: routes,
});

// 检查令牌是否过期
function isTokenExpired(token) {
  if (!token) return true;
  const decoded = jwtDecode(token);
  return decoded.exp < Date.now() / 1000;
}

function showLoginAlert(loginStore) {
  ElMessageBox.alert('您没有权限访问该页面，请先登录！', '权限提示', {
    confirmButtonText: '确定',
    callback: () => {
      loginStore.logout();
      window.location.href = '/login';
    },
  });
}

// 前置守卫，限制未登录的用户访问系统
router.beforeEach(async (to, from, next) => {
  try {
    const accessToken =
      localStorage.getItem('accessToken') ||
      sessionStorage.getItem('accessToken');
    const refreshToken =
      localStorage.getItem('refreshToken') ||
      sessionStorage.getItem('refreshToken');
    const rememberMe = localStorage.getItem('rememberMe') === 'true';
    const loginStore = useLoginStore();
    const userInfo = loginStore.getUserInfo;
    // const userRole = userInfo ? userInfo.role : 'user';
    const userRole = JSON.parse(localStorage.getItem('user'))?.role;
    // console.log({userInfo});
    // console.log({userRole});
    // console.log('beforeeach router:', router.getRoutes());
    // // 动态添加路由
    // console.log('bool:1', router.hasRoute('home-user-mange'));
    // if (userRole === 'admin' && !router.hasRoute('home-user-mange')) {
    //   router.addRoute('home', adminChildRoute); // 'home' 是父路由的 name
    // }
    // // console.log('bool:2',router.hasRoute('home-user-mange'));
    // console.log('beforeeach router:', router.getRoutes());

    console.log('路由守卫的userInfo：', userInfo);
    // 如果需要登录的页面
    if (to.meta.requiresAuth) {
      console.log(rememberMe);
      console.log('loginStore.isLoggedIn:', loginStore.isLoggedIn);
      if (!isTokenExpired(accessToken) && loginStore.isLoggedIn) {
        // 有 accessToken没过期 且已登录，直接放行
        if (to.meta.requiresAdmin && userRole !== 'admin') {
          // 超级管理员页面，但用户不是超级管理员
          ElMessageBox.alert('您没有权限访问该页面！', '权限提示', {
            confirmButtonText: '确定',
            callback: () => {
              next(false);
            },
          });
          return;
        }
        next();
      } else if (isTokenExpired(accessToken) && !isTokenExpired(refreshToken)) {
        // 不管勾选“七天免登录”与否，refreshToken存在且未过期，尝试刷新 accessToken（无感刷新）
        try {
          const res = await api.post(
            '/api/refresh_token',
            {},
            {
              headers: { Authorization: `Bearer ${refreshToken}` },
            },
          ); // 使用 refreshToken 作为 Authorization
          console.log('res.token: ', res.data);
          const newAccessToken = res.data.data.accessToken;
          if (rememberMe) {
            localStorage.setItem('accessToken', newAccessToken);
          } else {
            sessionStorage.setItem('accessToken', newAccessToken);
          }
          loginStore.setLogin(userInfo); // 标记为已登录
          localStorage.setItem('user', JSON.stringify(userInfo));
          next();
        } catch (err) {
          console.error('刷新 token 失败', err);
          // 刷新失败，跳转登录页
          showLoginAlert(loginStore);
          return;
        }
      } else {
        // 其他情况都视为未登录
        // 比如：未勾选“七天免登录”，开启新会话时无accessToken也无refreshToken
        showLoginAlert(loginStore);
        next(false);
        return;
      }
    } else {
      // 不需要登录的页面，直接放行
      next();
    }
  } catch (err) {
    console.error('路由守卫发生错误：', err);
    next('/login'); // 出现错误时直接跳转到登录页
  }
});

// 初始化用户信息（页面刷新时）
router.beforeResolve(async (to, from, next) => {
  const loginStore = useLoginStore();
  loginStore.initUserInfo();
  next();
});

export default router;
