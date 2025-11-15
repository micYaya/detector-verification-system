<template>
    <div class="list-container">
        <!-- 面包屑导航 -->
        <el-breadcrumb separator="/" class="breadcrumb">
            <el-breadcrumb-item>首页</el-breadcrumb-item>
            <el-breadcrumb-item>实验任务管理</el-breadcrumb-item>
            <el-breadcrumb-item>检测项目管理</el-breadcrumb-item>
        </el-breadcrumb>
        <div class="upper-section">
            <!-- 显示设备编号和任务ID -->
            <div class="device-info">
                <span>当前设备编号：{{ deviceId }}</span
                ><br />
                <span v-if="taskId">当前任务编号：{{ taskId }}</span>
            </div>
            <!-- 搜索和筛选区域 -->
            <div class="search-filter">
                <el-input
                    v-model="searchKeyword"
                    placeholder="请输入项目名称"
                    style="width: 250px; margin: 10px 0"
                    @keyup.enter="searchItems"
                />
                <el-button type="primary" @click="searchItems">
                    搜索
                </el-button>
            </div>
            <!-- 操作按钮区域 -->
            <div class="action-buttons">
                <el-button type="danger" @click="batchDelete">
                    批量删除
                </el-button>
                <el-button type="warning" @click="addItem">
                    添加检测项目
                </el-button>
                <el-button type="primary" @click="backToTaskList">
                    返回任务列表
                </el-button>
            </div>
        </div>
        <br />
        <div class="lower-section">
            <!-- 检测项目表格 -->
            <el-table
                :data="pagedItemList"
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
                <el-table-column
                    prop="item_id"
                    label="检测项目ID"
                    width="120"
                />
                <el-table-column prop="project" label="项目" width="100" />
                <el-table-column prop="gear" label="档位" width="100" />
                <el-table-column
                    prop="percentage"
                    label="百分比(%)"
                    width="120"
                />
                <el-table-column
                    prop="data_lower_limit"
                    label="数据下限(%)"
                    width="150"
                />
                <el-table-column
                    prop="data_upper_limit"
                    label="数据上限(%)"
                    width="150"
                />
                <el-table-column
                    prop="measured_data"
                    label="实测数据(%)"
                    width="150"
                />
                <el-table-column
                    prop="task_id"
                    label="关联任务ID"
                    width="120"
                />
                <el-table-column label="操作" fixed="right" min-width="200">
                    <template #default="scope">
                        <a
                            href="javascript:void(0)"
                            @click="editItem(scope.row)"
                            >编辑</a
                        >
                        <span class="divider">|</span>
                        <a
                            href="javascript:void(0)"
                            @click="viewItem(scope.row)"
                            >查看详情</a
                        >
                        <span class="divider">|</span>
                        <a
                            href="javascript:void(0)"
                            @click="deleteConfirm(scope.row)"
                            >删除</a
                        >
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
        <!-- 编辑检测项目对话框 -->
        <EditItem
            :item-info="editItemInfo"
            :is-edit-visible="isEditVisible"
            @close="isEditVisible = false"
            @refresh="fetchItems"
        />
        <!-- 查看检测项目详情对话框 -->
        <ViewItem
            :item-info="viewItemInfo"
            :is-view-visible="isViewVisible"
            @close="isViewVisible = false"
        />
        <!-- 添加检测项目对话框 -->
        <AddItem
            :is-add-visible="isAddVisible"
            :device-id="deviceId"
            :task-id="taskId"
            @close="isAddVisible = false"
            @refresh="fetchItems"
        />
    </div>
</template>

<script setup>
import { ref, onMounted, computed } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import EditItem from './EditItem.vue';
import ViewItem from './ViewItem.vue';
import AddItem from './AddItem.vue';
import { ElMessageBox, ElMessage } from 'element-plus';
import { getInspectionItems, delete_inspectionItem } from '@/api/request.js';

// 检测项目列表
const itemList = ref([]);
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

// 设定添加检测项目对话框初始状态
const isAddVisible = ref(false);
// 编辑检测项目相关
const editItemInfo = ref({});
const isEditVisible = ref(false);
// 查看检测项目详情相关
const viewItemInfo = ref({});
const isViewVisible = ref(false);

// 获取路由信息
const route = useRoute();
const router = useRouter();
const deviceId = ref(route.query.deviceId || '');
const taskId = ref(route.params.taskId || '');
const status = ref(route.query.status || '未开始');

const pagedItemList = computed(() => {
    const start = (currentPage.value - 1) * pageSize.value;
    const end = start + pageSize.value;
    return itemList.value.slice(start, end);
});

// 获取检测项目列表
const fetchItems = async () => {
    try {
        // const response = await api.get('/api/inspection_items');
        const response = await getInspectionItems();
        if (taskId.value) {
            itemList.value = response.filter(
                item => item.task_id == taskId.value
            );
        } else {
            itemList.value = response;
        }
        total.value = itemList.value.length;
    } catch (error) {
        console.error('获取检测项目列表失败', error);
    }
};

// 绑定点击函数
const addItem = () => {
    if (status.value === '已完成') {
        ElMessage.warning('实验已完成，不允许添加检测项目');
        return;
    }
    isAddVisible.value = true;
};

// 编辑检测项目方法
const editItem = row => {
    if (status.value === '已完成') {
        ElMessage.warning('实验状态已完成，不允许修改检测项目信息');
        return;
    }
    editItemInfo.value = { ...row };
    isEditVisible.value = true;
};

// 查看检测项目详情方法
const viewItem = row => {
    viewItemInfo.value = { ...row };
    isViewVisible.value = true;
};

const handleSelectionChange = rows => {
    selectedRows.value = rows;
    isIndeterminate.value =
        rows.length > 0 && rows.length < itemList.value.length;
    if (rows.length === itemList.value.length) {
        isIndeterminate.value = false;
    }
};

const handleSelectAll = selection => {
    if (selection.length === itemList.value.length) {
        isIndeterminate.value = false;
    } else if (selection.length > 0) {
        isIndeterminate.value = true;
    } else {
        isIndeterminate.value = false;
    }
    selectedRows.value = selection;
};

const selectable = () => true;

// 搜索检测项目方法
const searchItems = async () => {
    try {
        // const response = await api.get('/api/inspection_items');

        const response = await getInspectionItems();
        if (taskId.value) {
            itemList.value = response.filter(
                item => item.task_id == taskId.value
            );
        } else {
            itemList.value = response;
        }
        itemList.value = itemList.value.filter(item =>
            item.project.includes(searchKeyword.value)
        );
        total.value = itemList.value.length;
        currentPage.value = 1;
    } catch (error) {
        console.error('搜索检测项目信息失败', error);
    }
};

// 批量删除方法
const batchDelete = async () => {
    try {
        const ids = selectedRows.value.map(row => row.item_id);
        for (const id of ids) {
            // await api.delete(`/api/inspection_items/${id}`);
            await delete_inspectionItem(id);
        }
        await fetchItems();
    } catch (error) {
        console.error('批量删除检测项目信息失败', error);
    }
};

// 删除检测项目方法
const deleteItem = async id => {
    try {
        // await api.delete(`/api/inspection_items/${id}`);
        await delete_inspectionItem(id);
        await fetchItems();
    } catch (error) {
        console.error('删除检测项目信息失败', error);
    }
};

// 删除确认提示框
const deleteConfirm = row => {
    ElMessageBox.confirm('请问您是否要删除该检测项目信息?', '提示', {
        confirmButtonText: '确定',
        cancelButtonText: '取消',
        type: 'warning',
    })
        .then(() => {
            deleteItem(row.item_id);
        })
        .catch(() => {
            // 用户取消操作
        });
};

// 分页大小改变时的回调
const handleSizeChange = newSize => {
    pageSize.value = newSize;
};

// 当前页码改变时的回调
const handleCurrentChange = newPage => {
    currentPage.value = newPage;
};

// 返回任务列表
const backToTaskList = () => {
    router.push('/home/task-info');
};

onMounted(() => {
    fetchItems();
});
</script>

<style lang="less" scoped>
@import url('@/views/list_share.less');
@import url('@/views/modal.less');

.device-info {
    margin-bottom: 10px;
}
</style>
