<template>
    <div class="list-container">
        <!-- 面包屑导航 -->
        <el-breadcrumb separator="/" class="breadcrumb">
            <el-breadcrumb-item>首页</el-breadcrumb-item>
            <el-breadcrumb-item>实验任务管理</el-breadcrumb-item>
            <el-breadcrumb-item>结果管理</el-breadcrumb-item>
        </el-breadcrumb>

        <div class="upper-section">
            <!-- 搜索和筛选区域 -->
            <div class="search-filter">
                <el-input
                    v-model="searchKeyword"
                    placeholder="请输入关联设备编号"
                    style="width: 250px; margin: 10px 0"
                    @keyup.enter="searchResults"
                />
                <el-button type="primary" @click="searchResults">
                    搜索
                </el-button>
            </div>
            <!-- 操作按钮区域 -->
            <div class="action-buttons">
                <el-button type="danger" @click="batchDelete">
                    批量删除
                </el-button>
                <el-button type="warning" @click="addResult">
                    添加结果
                </el-button>
            </div>
        </div>

        <br />
        <div class="lower-section">
            <!-- 结果表格 -->
            <el-table
                :data="resultList"
                border
                style="width: 100%; margin-top: 20px"
                :cell-style="{ textAlign: 'center' }"
                :header-cell-style="{ textAlign: 'center' }"
                @selection-change="handleSelectionChange"
            >
                <el-table-column
                    type="selection"
                    width="60"
                    :indeterminate="isIndeterminate"
                    :selectable="selectable"
                    @select-all="handleSelectAll"
                />
                <el-table-column prop="resultId" label="结果编号" width="160" />
                <el-table-column
                    prop="deviceId"
                    label="关联设备编号"
                    width="160"
                />
                <el-table-column prop="twoP" label="二次电压" width="160" />
                <el-table-column prop="testDate" label="测试日期" width="160">
                    <template #default="scope">
                        {{ formatDate(scope.row.testDate) }}
                    </template>
                </el-table-column>
                <el-table-column prop="rate" label="r%" width="160" />
                <el-table-column label="操作" fixed="right" min-width="200">
                    <template #default="scope">
                        <a
                            href="javascript:void(0)"
                            @click="editResult(scope.row)"
                            >编辑</a
                        >
                        <span class="divider">|</span>
                        <a
                            href="javascript:void(0)"
                            @click="viewResult(scope.row)"
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
        <!-- 编辑结果对话框 -->
        <EditResult
            :result-info="editResultInfo"
            :is-edit-visible="isEditVisible"
            @close="isEditVisible = false"
            @refresh="fetchResults"
        />
        <!-- 查看结果详情对话框 -->
        <ViewResult
            :result-info="viewResultInfo"
            :is-view-visible="isViewVisible"
            @close="isViewVisible = false"
        />
        <!-- 添加结果对话框 -->
        <AddResult
            :is-add-visible="isAddVisible"
            @close="isAddVisible = false"
            @refresh="fetchResults"
        />
    </div>
</template>

<script setup>
import { ref } from 'vue';
import EditResult from './EditResult.vue';
import ViewResult from './ViewResult.vue';
import AddResult from './AddResult.vue';
import { ElMessageBox } from 'element-plus';
import { getResults, delete_result } from '@/api/request.js';
import { format } from 'date-fns';

// 结果列表
const resultList = ref([]);
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
const fullResultList = ref([]); // 原始数据

// 设定添加结果对话框初始状态
const isAddVisible = ref(false);
// 编辑结果相关
const editResultInfo = ref({});
const isEditVisible = ref(false);
// 查看结果详情相关
const viewResultInfo = ref({});
const isViewVisible = ref(false);

// 日期格式化计算属性
const formatDate = dateStr => {
    if (!dateStr) return '';
    return format(new Date(dateStr), 'yyyy-MM-dd');
};

// 获取结果列表
const fetchResults = async () => {
    try {
        // const response = await api.get('/api/results');
        fullResultList.value = await getResults();
        // fullResultList.value = response.data;
        total.value = fullResultList.value.length;

        // 分页处理
        const startIndex = (currentPage.value - 1) * pageSize.value;
        const endIndex = startIndex + pageSize.value;
        resultList.value = fullResultList.value.slice(startIndex, endIndex);
    } catch (error) {
        console.error('获取结果列表失败', error);
    }
};

// 绑定点击函数
const addResult = () => {
    isAddVisible.value = true;
};

// 编辑结果方法
const editResult = row => {
    editResultInfo.value = { ...row };
    isEditVisible.value = true;
};

// 查看结果详情方法
const viewResult = row => {
    viewResultInfo.value = { ...row };
    isViewVisible.value = true;
};

const handleSelectionChange = rows => {
    selectedRows.value = rows;
    isIndeterminate.value =
        rows.length > 0 && rows.length < resultList.value.length;
    if (rows.length === resultList.value.length) {
        isIndeterminate.value = false;
    }
};

const handleSelectAll = selection => {
    if (selection.length === resultList.value.length) {
        isIndeterminate.value = false;
    } else if (selection.length > 0) {
        isIndeterminate.value = true;
    } else {
        isIndeterminate.value = false;
    }
    selectedRows.value = selection;
};

const selectable = () => true;

// 搜索结果方法
const searchResults = async () => {
    // const response = await api.get('/api/results');
    const response = await getResults();
    const filtered = response.filter(result =>
        String(result.deviceId).includes(searchKeyword.value)
    );
    fullResultList.value = filtered;
    total.value = filtered.length;

    // 分页处理
    const startIndex = (currentPage.value - 1) * pageSize.value;
    const endIndex = startIndex + pageSize.value;
    resultList.value = filtered.slice(startIndex, endIndex);
};

// 批量删除方法
const batchDelete = async () => {
    try {
        const ids = selectedRows.value.map(row => row.resultId);
        for (const id of ids) {
            // await api.delete(`/api/results/${id}`);
            await delete_result(id);
        }
        await fetchResults();
    } catch (error) {
        console.error('批量删除结果信息失败', error);
    }
};

// 删除结果方法
const deleteResult = async id => {
    try {
        // await api.delete(`/api/results/${id}`);
        await delete_result(id);
        await fetchResults();
    } catch (error) {
        console.error('删除结果信息失败', error);
    }
};

// 删除确认提示框
const deleteConfirm = row => {
    ElMessageBox.confirm('请问您是否要删除该结果信息?', '提示', {
        confirmButtonText: '确定',
        cancelButtonText: '取消',
        type: 'warning',
    })
        .then(() => {
            deleteResult(row.resultId);
        })
        .catch(() => {
            // 用户取消操作
        });
};

// 分页大小改变时的回调
const handleSizeChange = newSize => {
    pageSize.value = newSize;
    currentPage.value = 1; // 重置为第一页
    fetchResults(); // 重新获取分页数据
};

// 当前页码改变时的回调
const handleCurrentChange = newPage => {
    currentPage.value = newPage;
    fetchResults(); // 切换分页
};

// 初始化时获取结果列表
fetchResults();
</script>

<style lang="less" scoped>
@import url('@/views/list_share.less');
</style>
