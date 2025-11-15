<template>
    <div>
        <div class="header">
            <div class="user">
                <span class="time">{{ currentTime }}</span>
                <el-dropdown class="avatar-container">
                    <div class="user-info">
                        <img
                            class="avatar"
                            src="@/static/images/user_default.png"
                            alt="默认头像"
                        />
                        <!-- 在Vue模板中，计算属性ComputeRef会自动解包，无需手动通过.value取值 -->
                        <span v-if="userinfo">{{ userinfo.username }}</span>
                    </div>
                    <template #dropdown>
                        <el-dropdown-menu>
                            <el-dropdown-item>个人信息</el-dropdown-item>
                            <el-dropdown-item @click="resetPassword">
                                修改密码
                            </el-dropdown-item>
                            <el-dropdown-item @click="loginout">
                                退出登录
                            </el-dropdown-item>
                        </el-dropdown-menu>
                    </template>
                </el-dropdown>
                <!-- <a v-if="userinfo" class="login-out" @click="loginout">退出登录</a> -->
            </div>
        </div>

        <!-- 内容区域，路由出口 -->
        <div class="main-content">
            <!-- 根据menu选项来显示对应组件 -->
            <router-view />
        </div>
    </div>
</template>

<script setup>
import { computed, ref, onMounted, onUnmounted } from 'vue';
import { useRouter } from 'vue-router';
import { useLoginStore } from '@/store/index.js';
import { ElMessageBox } from 'element-plus';

const loginStore = useLoginStore();
const router = useRouter();
const userinfo = computed(() => loginStore.getUserInfo);
console.log(userinfo);
// 时间处理
const currentTime = ref('');
const updateTime = () => {
    const date = new Date();
    currentTime.value = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}  ${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}:${String(date.getSeconds()).padStart(2, '0')}`;
};

onMounted(() => {
    updateTime();
    setInterval(updateTime, 1000);
});

onUnmounted(() => {
    clearInterval(updateTime);
});

const loginout = async () => {
    try {
        await ElMessageBox.confirm('确定要退出登录吗？', '提示', {
            confirmButtonText: '确定',
            cancelButtonText: '取消',
            type: 'warning',
        });
        loginStore.logout();
        router.push('/login');
    } catch (error) {
        console.log('用户取消退出', error);
    }
};

const resetPassword = () => {
    router.push('/forget-password');
};
</script>

<style lang="less" scoped>
.header {
    position: relative;
    height: 8vh;
    line-height: 45px;
    color: #fff;
    background: #1e78bf;
    display: flex;
    justify-content: flex-end;
    align-items: center;
    padding: 0 40px;
    box-sizing: border-box;
    margin-left: auto;

    .user {
        display: flex;
        align-items: center;
        gap: 10px;

        .time {
            margin-right: 10px;
        }

        .user-info {
            display: flex;
            align-items: center;

            span {
                margin: 0 8px;
            }
        }

        .avatar-container {
            cursor: pointer;
        }

        .avatar {
            width: 30px;
            border-radius: 50%;
            background-color: white;
            max-width: 100%;
            height: auto;
        }

        .login-out {
            font-size: 20px;
            cursor: pointer;
        }
    }
}

.main-content {
    width: 82%;
    position: absolute;
    top: 11vh;
    left: 16%;
    height: calc(100vh - 11vh);
    overflow: auto;
}

:deep(.el-dropdown) {
    color: white;
}

@media screen and (width <= 600px) {
    .main-content {
        left: 22% !important;
    }

    .user {
        .time {
            display: none;
        }

        .login-out {
            display: none;
        }
    }
}
</style>
