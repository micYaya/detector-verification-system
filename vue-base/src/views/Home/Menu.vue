<template>
    <div class="menu-container" :class="{ collapsed: props.isCollapsed }">
        <div class="logo">
            <img class="avatar" src="@/static/images/logo.jpg" alt="系统图标" />
            <p v-if="!props.isCollapsed">检测仪检定系统</p>
        </div>
        <ul>
            <li
                :class="[{ active: currentPath === '/home/' }, 'li-hover']"
                @click="goToPage('/')"
            >
                <!-- <el-icon><HomeFilled /></el-icon> -->
                <!-- <span v-if="!isCollapsed">主页</span> -->
                <el-tooltip
                    v-if="props.isCollapsed"
                    content="主页"
                    placement="right"
                >
                    <el-icon><HomeFilled /></el-icon>
                </el-tooltip>
                <template v-else>
                    <el-icon><HomeFilled /></el-icon><span>主页</span>
                </template>
            </li>
            <li
                :class="[
                    { active: currentPath === '/home/device-info' },
                    'li-hover',
                ]"
                @click="goToPage('/device-info')"
            >
                <!-- <el-icon><Menu /></el-icon><span v-if="!isCollapsed">设备信息管理</span> -->
                <el-tooltip
                    v-if="props.isCollapsed"
                    content="设备信息管理"
                    placement="right"
                >
                    <el-icon><Menu /></el-icon>
                </el-tooltip>
                <template v-else>
                    <el-icon><Menu /></el-icon><span>设备信息管理</span>
                </template>
            </li>

            <!-- 多级：实验任务管理 -->
            <el-popover
                v-if="props.isCollapsed"
                placement="right-start"
                width="200"
                trigger="hover"
                popper-class="custom-popover"
            >
                <template #reference>
                    <li>
                        <el-icon><Menu /></el-icon>
                    </li>
                </template>
                <ul class="submenu">
                    <li @click="goToPage('/task-info')">任务管理</li>
                    <li @click="goToPage('/result-info')">结果管理</li>
                </ul>
            </el-popover>
            <li v-else>
                <el-icon><Menu /></el-icon><span>实验任务管理</span>
                <ul class="submenu">
                    <li
                        :class="[
                            { active: currentPath === '/home/task-info' },
                            'li-hover',
                        ]"
                        @click="goToPage('/task-info')"
                    >
                        <el-icon><Menu /></el-icon>任务管理
                    </li>
                    <li
                        :class="[
                            { active: currentPath === '/home/result-info' },
                            'li-hover',
                        ]"
                        @click="goToPage('/result-info')"
                    >
                        <el-icon><Menu /></el-icon>结果管理
                    </li>
                </ul>
            </li>

            <li
                :class="[
                    { active: currentPath === '/home/report-info' },
                    'li-hover',
                ]"
                @click="goToPage('/report-info')"
            >
                <!-- <el-icon><Printer /></el-icon><span v-if="!isCollapsed">实验报表打印</span> -->
                <el-tooltip
                    v-if="props.isCollapsed"
                    content="实验报表打印"
                    placement="right"
                >
                    <el-icon><Printer /></el-icon>
                </el-tooltip>
                <template v-else>
                    <el-icon><Printer /></el-icon><span>实验报表打印</span>
                </template>
            </li>
            <li
                :class="[
                    { active: currentPath === '/home/statistic-info' },
                    'li-hover',
                ]"
                @click="goToPage('/statistic-info')"
            >
                <!-- <el-icon><Histogram /></el-icon><span v-if="!isCollapsed">统计与分析</span> -->
                <el-tooltip
                    v-if="props.isCollapsed"
                    content="统计与分析"
                    placement="right"
                >
                    <el-icon><Histogram /></el-icon>
                </el-tooltip>
                <template v-else>
                    <el-icon><Histogram /></el-icon><span>统计与分析</span>
                </template>
            </li>

            <!-- 用户管理（仅 admin 显示） -->
            <li
                v-if="userRole === 'admin'"
                :class="[
                    { active: currentPath === '/home/user-manage' },
                    'li-hover',
                ]"
                @click="goToPage('/user-manage')"
            >
                <el-tooltip
                    v-if="props.isCollapsed"
                    content="用户管理"
                    placement="right"
                >
                    <el-icon><UserFilled /></el-icon>
                </el-tooltip>
                <template v-else>
                    <el-icon><UserFilled /></el-icon><span>用户管理</span>
                </template>
            </li>
        </ul>
    </div>
</template>

<script setup>
import { useRouter, useRoute } from 'vue-router';
import { ref, watch } from 'vue';
import { useLoginStore } from '@/store/index.js';

const router = useRouter();
const route = useRoute();
const currentPath = ref(route.path);
const props = defineProps({
    isCollapsed: Boolean,
});

// 获取用户角色
const loginStore = useLoginStore();
const userRole = ref(loginStore.getUserInfo?.role || 'user'); // 默认为普通用户

watch(
    () => route.path,
    newPath => {
        currentPath.value = newPath;
        // console.log(currentPath.value);
    }
);
// 监听用户角色变化
watch(
    () => loginStore.getUserInfo,
    userInfo => {
        if (userInfo) {
            userRole.value = userInfo.role; // 更新角色状态
        }
    },
    { immediate: true } // 组件加载时立即获取角色
);
const goToPage = path => {
    if (path === '/user-manage' && !router.hasRoute('home-user-manage')) return;
    router.push('/home' + path);
};
</script>

<style lang="less" scoped>
.menu-container {
    width: 100%;
    height: 100%;
    background-color: #1e78bf;
    color: white;
    border-color: white;
    transition: width 0.3s ease;

    /* 隐藏滚动条 */
    overflow: -moz-scrollbars-none; /* Firefox */
    -ms-overflow-style: none; /* Internet Explorer 10+ */

    /* 为webkit内核浏览器添加样式 */
    &::-webkit-scrollbar {
        display: none;
    }

    &.collapsed {
        width: 80px;

        ul li {
            justify-content: center;
            padding: 12px 10px;

            span {
                display: none;
            }
        }

        .logo {
            justify-content: center;

            p {
                display: none;
            }
        }
    }

    .logo {
        display: flex;
        flex-direction: row;
        padding: 12px 2px 4px 10px;

        .avatar {
            width: 35px;
            height: 35px;
            border-radius: 10%;
            max-width: 100%;
        }

        p {
            font-size: 25px;

            /* font-size: 1.875rem; */
            margin: 0 8px;
        }
    }

    ul {
        list-style-type: none;
        padding: 0;
        margin: 10px 10px 10px 4px;
        line-height: 20px;

        li {
            padding: 12px 16px;

            /* padding: 0.75rem 1.25rem; */
            cursor: pointer;
            font-size: 20px;

            /* font-size: 1.25rem; */
            border-bottom: 1px solid rgb(255 255 255 / 10%);
            transition: background-color 0.3s ease;

            :deep(.el-icon) {
                width: 40px;
                height: 40px;
                margin: 0 5px;
            }
        }

        .li-hover:hover {
            background-color: #0056b3;
        }
    }

    .active {
        /* background-color: #1e99ff; */
        background-color: #0056b3;
    }
}

.submenu {
    list-style: none;
    padding: 0;
    margin: 0;

    li {
        padding: 10px 16px;
        cursor: pointer;
        font-size: 16px;

        &:hover {
            background-color: #f5f7fa;
        }
    }
}

:deep(.custom-popover) {
    padding: 0;
}
</style>
