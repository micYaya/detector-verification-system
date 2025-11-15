<template>
    <div class="list-container">
        <!-- 面包屑导航 -->
        <el-breadcrumb separator="/" class="breadcrumb">
            <el-breadcrumb-item>首页</el-breadcrumb-item>
            <el-breadcrumb-item>设备管理</el-breadcrumb-item>
        </el-breadcrumb>
        <!-- 上半部分区域 -->
        <div class="upper-section">
            <!-- 搜索和筛选区域 -->
            <div class="search-filter">
                <el-input
                    v-model="searchKeyword"
                    placeholder="请输入设备名称"
                    style="width: 250px; margin: 10px 0"
                    @keyup.enter="searchDevices"
                />
                <el-button type="primary" @click="searchDevices">
                    搜索
                </el-button>
            </div>
            <!-- 操作按钮区域 -->
            <div class="action-buttons">
                <el-button type="danger" @click="batchDelete">
                    批量删除
                </el-button>
                <el-button type="warning" @click="addDevice">
                    添加设备
                </el-button>
            </div>
        </div>
        <br />
        <!-- 下半部分区域 -->
        <div class="lower-section">
            <!-- 设备表格 -->
            <el-table
                :data="deviceList"
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
                <el-table-column prop="deviceId" label="设备ID" width="100" />
                <el-table-column
                    prop="deviceName"
                    label="设备名称"
                    width="100"
                />
                <el-table-column
                    prop="deviceModel"
                    label="设备型号"
                    width="100"
                />
                <el-table-column
                    prop="manufactureDate"
                    label="生产日期"
                    width="200"
                >
                    <template #default="scope">
                        {{ formatDate(scope.row.manufactureDate) }}
                    </template>
                </el-table-column>
                <el-table-column
                    prop="inspectionDate"
                    label="送检日期"
                    width="200"
                >
                    <template #default="scope">
                        {{ formatDate(scope.row.inspectionDate) }}
                    </template>
                </el-table-column>
                <el-table-column
                    prop="manufacturer"
                    label="制造商"
                    width="140"
                />
                <el-table-column
                    prop="productionPlace"
                    label="产地"
                    width="140"
                />
                <el-table-column
                    prop="deviceStatus"
                    label="设备状态"
                    width="100"
                />
                <el-table-column label="操作" fixed="right" min-width="200">
                    <template #default="scope">
                        <!-- <span @click="editDevice(scope.row)">编辑</span> -->
                        <a
                            href="javascript:void(0)"
                            @click="editDevice(scope.row)"
                            >编辑</a
                        >
                        <span class="divider">|</span>
                        <!-- <span @click="viewDevice(scope.row)">查看详情</span> -->
                        <a
                            href="javascript:void(0)"
                            @click="viewDevice(scope.row)"
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
            <!-- <div class="pagination-wrapper">
        <el-pagination
          :current-page="currentPage"
          :page-sizes="[5, 10, 15]"
          :page-size="pageSize"
          layout="total, prev, pager, next, sizes, jumper"
          :total="total"
          @size-change="handleSizeChange"
          @current-change="handleCurrentChange"
        />
      </div> -->
            <Pagination
                :current-page="currentPage"
                :page-size="pageSize"
                :total="total"
                @update:current-page="handleCurrentChange"
                @update:page-size="handleSizeChange"
            />
        </div>
        <!-- 编辑设备对话框 -->
        <EditDevice
            :device-info="editDeviceInfo"
            :is-edit-visible="isEditVisible"
            @close="isEditVisible = false"
            @refresh="fetchDevices"
        />
        <!-- 查看设备详情对话框 -->
        <ViewDevice
            :device-info="viewDeviceInfo"
            :is-view-visible="isViewVisible"
            @close="isViewVisible = false"
        />
        <!-- 添加设备对话框 -->
        <AddDevice
            :is-add-visible="isAddVisible"
            @close="isAddVisible = false"
            @refresh="fetchDevices"
        />
    </div>
</template>

<script setup>
import { ref } from 'vue';
import EditDevice from './EditDevice.vue';
import ViewDevice from './ViewDevice.vue';
import AddDevice from './AddDevice.vue';
import Pagination from '@/components/Pagination.vue';
import { ElMessageBox } from 'element-plus';
import { getDeviceList, delete_device } from '@/api/request.js';
import { format } from 'date-fns';

// 设备列表
const deviceList = ref([]);
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

// 设定添加设备对话框初始状态
const isAddVisible = ref(false);
// 编辑设备相关
const editDeviceInfo = ref({});
const isEditVisible = ref(false);
// 查看设备详情相关
const viewDeviceInfo = ref({});
const isViewVisible = ref(false);

// 日期格式化计算属性
const formatDate = dateStr => {
    if (!dateStr) return '';
    return format(new Date(dateStr), 'yyyy-MM-dd');
};

// 获取设备列表
const fetchDevices = async () => {
    try {
        // const response = await api.get('/api/devices');

        const allData = await getDeviceList();
        total.value = allData.length; // 总条数
        const startIndex = (currentPage.value - 1) * pageSize.value;
        const endIndex = startIndex + pageSize.value;

        deviceList.value = allData.slice(startIndex, endIndex); // 分页处理
    } catch (error) {
        console.error('获取设备列表失败', error);
    }
};

// 绑定点击函数
const addDevice = () => {
    isAddVisible.value = true;
};

// 编辑设备方法
const editDevice = row => {
    editDeviceInfo.value = { ...row };
    isEditVisible.value = true;
    // 刷新报表
    fetchDevices();
};

// 查看设备详情方法
const viewDevice = row => {
    viewDeviceInfo.value = { ...row };
    isViewVisible.value = true;
};

const handleSelectionChange = rows => {
    selectedRows.value = rows;
    isIndeterminate.value =
        rows.length > 0 && rows.length < deviceList.value.length;
    if (rows.length === deviceList.value.length) {
        isIndeterminate.value = false;
    }
};

const handleSelectAll = selection => {
    if (selection.length === deviceList.value.length) {
        isIndeterminate.value = false;
    } else if (selection.length > 0) {
        isIndeterminate.value = true;
    } else {
        isIndeterminate.value = false;
    }
    selectedRows.value = selection;
};

const selectable = () => true;

// 搜索设备方法
const searchDevices = async () => {
    try {
        // const response = await api.get('/api/devices');
        const response = await getDeviceList();
        const filtered = response.filter(device =>
            device.deviceName.includes(searchKeyword.value)
        );

        total.value = filtered.length;
        currentPage.value = 1; // 搜索后回到第一页
        const startIndex = 0;
        const endIndex = pageSize.value;

        deviceList.value = filtered.slice(startIndex, endIndex);
    } catch (error) {
        console.error('搜索设备信息失败', error);
    }
};

// 批量删除方法
const batchDelete = async () => {
    try {
        const ids = selectedRows.value.map(row => row.id);
        for (const id of ids) {
            // await api.delete(`/api/devices/${id}`);
            await delete_device(id);
        }
        await fetchDevices();
    } catch (error) {
        console.error('批量删除设备信息失败', error);
    }
};

// 删除设备方法
const deleteDevice = async id => {
    try {
        // await api.delete(`/api/devices/${id}`);
        await delete_device(id);
        await fetchDevices();
    } catch (error) {
        // console.error('删除设备信息失败', error);
    }
};

// 删除确认提示框
const deleteConfirm = row => {
    ElMessageBox.confirm('请问您是否要删除该设备信息信息?', '提示', {
        confirmButtonText: '确定',
        cancelButtonText: '取消',
        type: 'warning',
    })
        .then(() => {
            deleteDevice(row.id);
        })
        .catch(() => {
            // 用户取消操作
        });
};

// 分页大小改变时的回调
const handleSizeChange = newSize => {
    console.log('新的每页数量:', newSize);
    pageSize.value = newSize;
    fetchDevices(); // 触发数据重新获取
};

// 当前页码改变时的回调
const handleCurrentChange = newPage => {
    console.log('新的页码:', newPage);
    currentPage.value = newPage;
    fetchDevices(); // 触发数据重新获取
};

// 初始化时获取设备列表
fetchDevices();
</script>

<style lang="less" scoped>
@import url('@/views/list_share.less');
</style>
