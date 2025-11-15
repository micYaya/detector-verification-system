<template>
    <div class="list-container">
        <!-- 面包屑导航 -->
        <el-breadcrumb separator="/" class="breadcrumb">
            <el-breadcrumb-item>首页</el-breadcrumb-item>
            <el-breadcrumb-item>实验任务管理</el-breadcrumb-item>
            <el-breadcrumb-item>任务管理</el-breadcrumb-item>
        </el-breadcrumb>

        <div class="upper-section">
            <!-- 搜索和筛选区域 -->
            <div class="search-filter">
                <el-input
                    v-model="searchKeyword"
                    placeholder="请输入设备编号"
                    style="width: 250px; margin: 10px 0"
                    @keyup.enter="searchTasks"
                />
                <el-button type="primary" @click="searchTasks">
                    搜索
                </el-button>
            </div>
            <!-- 操作按钮区域 -->
            <div class="action-buttons">
                <el-button type="danger" @click="batchDelete">
                    批量删除
                </el-button>
                <el-button type="warning" @click="addTask">
                    添加任务
                </el-button>
            </div>
        </div>
        <br />

        <div class="lower-section">
            <!-- 任务表格 -->
            <el-table
                :data="taskList"
                border
                style="width: 100%; margin-top: 20px"
                :cell-style="{ textAlign: 'center' }"
                :header-cell-style="{ textAlign: 'center' }"
                @selection-change="handleSelectionChange"
            >
                <el-table-column
                    type="selection"
                    width="50"
                    :indeterminate="isIndeterminate"
                    :selectable="selectable"
                    @select-all="handleSelectAll"
                />
                <el-table-column prop="id" label="任务ID" width="100" />
                <el-table-column prop="deviceId" label="设备编号" width="100" />
                <el-table-column prop="status" label="实验状态" width="100" />
                <el-table-column prop="startTime" label="开始时间" width="200">
                    <template #default="scope">
                        {{
                            scope.row.startTime
                                ? formatDate(scope.row.startTime)
                                : ''
                        }}
                    </template>
                </el-table-column>
                <el-table-column prop="endTime" label="结束时间" width="200">
                    <template #default="scope">
                        {{
                            scope.row.endTime
                                ? formatDate(scope.row.endTime)
                                : ''
                        }}
                    </template>
                </el-table-column>
                <el-table-column
                    prop="item_count"
                    label="实验项目数量"
                    width="200"
                />
                <el-table-column label="操作" fixed="right" min-width="400">
                    <template #default="scope">
                        <el-button
                            type="primary"
                            @click="
                                goToItemList(
                                    scope.row.id,
                                    scope.row.deviceId,
                                    scope.row.status
                                )
                            "
                        >
                            实验项目管理
                        </el-button>
                        <el-button
                            type="warning"
                            :disabled="
                                scope.row.status === '已完成' ||
                                scope.row.item_count === 0
                            "
                            @click="confirmStartExperiment(scope.row)"
                        >
                            发起实验
                        </el-button>
                        <el-button
                            type="danger"
                            @click="deleteConfirm(scope.row)"
                        >
                            删除任务
                        </el-button>
                    </template>
                </el-table-column>
            </el-table>
            <!-- 分页组件 -->
            <div class="pagination-wrapper">
                <el-pagination
                    :current-page="currentPage"
                    :page-sizes="[5, 10, 15]"
                    :page-size="pageSize"
                    layout="total, prev, pager, next, sizes, jumper"
                    :total="total"
                    @size-change="handleSizeChange"
                    @current-change="handleCurrentChange"
                />
            </div>
        </div>

        <!-- 添加任务对话框 -->
        <AddTask
            :is-add-visible="isAddVisible"
            @close="isAddVisible = false"
            @refresh="fetchTasks"
        />
    </div>
</template>

<script setup>
import { ref, onMounted } from 'vue';
import AddTask from './AddTask.vue';
import { ElMessageBox } from 'element-plus';
import {
    getTaskListWithItemCount,
    updateTaskStatus,
    performOcr,
    delete_task,
    updateDeviceStatus,
} from '@/api/request.js';
import { format } from 'date-fns';
import { useRouter } from 'vue-router';

// 任务列表
const allTaskList = ref([]); // 保存所有任务列表
const taskList = ref([]); // 当前分页展示的数据
// 搜索关键字
const searchKeyword = ref('');
// 当前页码
const currentPage = ref(1);
// 每页数量
const pageSize = ref(5);
// 总数据量
const total = ref(0);
// 表格选择相关
const selectedRows = ref([]);
const isIndeterminate = ref(false);

// 设定添加任务对话框初始状态
const isAddVisible = ref(false);
const router = useRouter();

// 日期格式化计算属性
const formatDate = dateStr => {
    if (!dateStr) return '';
    return format(new Date(dateStr), 'yyyy-MM-dd HH:mm:ss');
};

// 获取任务列表
const fetchTasks = async () => {
    try {
        // const response = await api.get('/api/tasks/with-item-count');
        // allTaskList.value = response.data;

        allTaskList.value = await getTaskListWithItemCount();
        total.value = allTaskList.value.length;
        updateTaskList(); // 设置当前页数据
    } catch (error) {
        console.error('获取任务列表失败', error);
    }
};
const updateTaskList = () => {
    const start = (currentPage.value - 1) * pageSize.value;
    const end = start + pageSize.value;
    taskList.value = allTaskList.value.slice(start, end);
};
const handleSizeChange = size => {
    pageSize.value = size;
    currentPage.value = 1; // 重置为第一页
    updateTaskList();
};

const handleCurrentChange = page => {
    currentPage.value = page;
    updateTaskList();
};

// 绑定点击函数
const addTask = () => {
    isAddVisible.value = true;
};

// 实验项目管理
const goToItemList = (taskId, deviceId, status) => {
    router.push({
        name: 'item-info',
        params: { taskId },
        query: { deviceId, status },
    });
};

// 确认发起实验
const confirmStartExperiment = task => {
    ElMessageBox.confirm(
        `是否确定对设备编号为 ${task.deviceId} 发起实验？`,
        '提示',
        {
            confirmButtonText: '是',
            cancelButtonText: '否',
            type: 'warning',
        }
    )
        .then(() => {
            startExperiment(task);
        })
        .catch(() => {
            // 用户取消操作
        });
};

// 发起实验
const startExperiment = async task => {
    try {
        const now = new Date();
        const formattedTime = format(now, 'yyyy-MM-dd HH:mm:ss');

        // 更新实验状态为实验中
        // await api.put(`/api/tasks/${task.id}`, {
        await updateTaskStatus(task.id, {
            deviceId: task.deviceId,
            startTime: formattedTime,
            endTime: null,
            status: '实验中',
        });

        // 找到任务在列表中的索引
        const index = taskList.value.findIndex(item => item.id === task.id);
        if (index !== -1) {
            taskList.value[index].startTime = formattedTime;
            taskList.value[index].status = '实验中';
        }

        // 根据实验项目数量进行多次实验
        for (let i = 0; i < task.item_count; i++) {
            console.log(i);
            // const response = await api.post('/api/perform-ocr', { deviceId: task.deviceId });
            // const result = response.data;
            const result = await performOcr(task.deviceId);
            console.log(result);
        }

        // 设置定时器，5 秒后将状态改为已完成并记录结束时间
        setTimeout(async () => {
            const endTime = new Date();
            const formattedEndTime = format(endTime, 'yyyy-MM-dd HH:mm:ss');

            // await api.put(`/api/tasks/${task.id}`, {
            await updateTaskStatus(task.id, {
                deviceId: task.deviceId,
                startTime: task.startTime,
                endTime: formattedEndTime,
                status: '已完成',
            });
            // 更新设备状态
            await updateDeviceStatus(task.deviceId, '检测完成');

            await fetchTasks(); // 强制刷新任务列表
        }, 5000);
    } catch (error) {
        console.error('发起实验失败', error);
    }
};

const handleSelectionChange = rows => {
    selectedRows.value = rows;
    isIndeterminate.value =
        rows.length > 0 && rows.length < taskList.value.length;
    if (rows.length === taskList.value.length) {
        isIndeterminate.value = false;
    }
};

const handleSelectAll = selection => {
    if (selection.length === taskList.value.length) {
        isIndeterminate.value = false;
    } else if (selection.length > 0) {
        isIndeterminate.value = true;
    } else {
        isIndeterminate.value = false;
    }
    selectedRows.value = selection;
};

const selectable = () => true;

// 搜索任务方法
const searchTasks = async () => {
    try {
        // const response = await api.get('/api/tasks/with-item-count');
        const response = await getTaskListWithItemCount();
        const filtered = response.filter(task =>
            task.deviceId.includes(searchKeyword.value)
        );
        allTaskList.value = filtered;
        total.value = filtered.length;
        currentPage.value = 1; // 重置分页
        updateTaskList();
    } catch (error) {
        console.error('搜索任务信息失败', error);
    }
};

// 批量删除方法
const batchDelete = async () => {
    try {
        // const ids = selectedRows.value.map((row) => row.id);

        for (const selectedTask of selectedRows.value) {
            // await api.delete(`/api/tasks/${id}`);
            // await delete_task(id);
            await delete_task(selectedTask.id);
            await updateDeviceStatus(selectedTask.deviceId, '未检测');
        }
        await fetchTasks();
    } catch (error) {
        console.error('批量删除任务信息失败', error);
    }
};

// 删除任务方法
const deleteTask = async task => {
    try {
        // await api.delete(`/api/tasks/${id}`);
        await delete_task(task.id);
        // 删除完任务后，相关的设备状态、结果都得一起删掉
        await updateDeviceStatus(task.deviceId, '未检测');
        await fetchTasks();
    } catch (error) {
        console.error('删除任务信息失败', error);
    }
};

// 删除确认提示框
const deleteConfirm = row => {
    ElMessageBox.confirm('请问您是否要删除该任务信息?', '提示', {
        confirmButtonText: '确定',
        cancelButtonText: '取消',
        type: 'warning',
    })
        .then(() => {
            deleteTask(row);
            // deleteTask(row.id);
        })
        .catch(() => {
            // 用户取消操作
        });
};

// 初始化时获取任务列表
onMounted(() => {
    fetchTasks();
});
</script>

<style lang="less" scoped>
@import url('@/views/list_share.less');
</style>
