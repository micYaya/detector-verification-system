<template>
    <div class="list-container">
        <!-- 面包屑导航 -->
        <el-breadcrumb separator="/" class="breadcrumb">
            <el-breadcrumb-item>首页</el-breadcrumb-item>
            <el-breadcrumb-item>报表管理</el-breadcrumb-item>
        </el-breadcrumb>
        <div class="upper-section">
            <!-- 搜索和筛选区域 -->
            <div class="search-filter">
                <el-input
                    v-model="searchDeviceId"
                    placeholder="请输入设备编号"
                    style="width: 250px; margin: 10px 0"
                    @keyup.enter="searchReports"
                />
                <el-button type="primary" @click="searchReports">
                    搜索
                </el-button>
            </div>
        </div>
        <br />
        <div class="lower-section">
            <el-skeleton v-if="loading" row="5" animated />
            <!-- 报表表格 -->
            <el-table
                v-else
                :data="paginatedReportList"
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
                <el-table-column prop="status" label="实验状态" width="100" />
                <el-table-column
                    prop="inspectionDate"
                    label="送检日期"
                    width="260"
                >
                    <template #default="scope">
                        {{ formatDate(scope.row.inspectionDate) }}
                    </template>
                </el-table-column>
                <el-table-column
                    prop="endTime"
                    label="实验结束时间"
                    width="250"
                >
                    <template #default="scope">
                        {{ formatDate(scope.row.endTime) }}
                    </template>
                </el-table-column>
                <el-table-column label="操作" fixed="right" min-width="200">
                    <template #default="scope">
                        <a
                            href="javascript:void(0)"
                            :disabled="scope.row.status !== '已完成'"
                            :class="{
                                'disabled-link': scope.row.status !== '已完成',
                            }"
                            @click="viewReport(scope.row)"
                        >
                            查看报表
                        </a>
                        <span class="divider">|</span>
                        <a
                            href="javascript:void(0)"
                            :disabled="scope.row.status !== '已完成'"
                            :class="{
                                'disabled-link': scope.row.status !== '已完成',
                            }"
                            @click="printReport(scope.row)"
                        >
                            打印报表
                        </a>
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
        <!-- 查看报表对话框 -->
        <ViewReport
            :report-info="viewReportInfo"
            :is-view-visible="isViewVisible"
            @close="isViewVisible = false"
        />
    </div>
</template>

<script setup>
import { ref, onMounted, computed } from 'vue';
import ViewReport from './ViewReport.vue';
import { getDeviceList, getReport, getTaskList } from '@/api/request.js';
import { format } from 'date-fns';
import jsPDF from 'jspdf';
// import { autoTable } from 'jspdf-autotable';

import '@/static/fonts/SourceHanSansCN-Normal-normal.js'; // 引入中文字体文件

// 用于骨架屏
const loading = ref(false);

// 报表列表
const reportList = ref([]);
// 搜索关键字
const searchDeviceId = ref('');
// 过滤得到的报表列表
const filteredReportList = ref([]);
// 当前页码
const currentPage = ref(1);
// 每页数量
const pageSize = ref(5);
// 总数据量
const total = ref(0);
// 表格选择相关
const selectedRows = ref([]);
const isIndeterminate = ref(false);

// 查看报表相关
const viewReportInfo = ref({});
const isViewVisible = ref(false);

// 日期格式化计算属性
const formatDate = dateStr => {
    if (!dateStr) return '';
    return format(new Date(dateStr), 'yyyy-MM-dd HH:mm:ss');
};

// 获取报表列表
const fetchReports = async () => {
    loading.value = true;

    // 分页加载
    try {
        // 先获得设备数据
        // const response = await api.get('/api/devices');
        // console.log('devices info:', response.data);
        // const devices = response.data;

        const devices = await getDeviceList();

        // 再通过设备Id获得实验数据:status、endTime
        const tasksPromises = devices.map(async device => {
            // const taskResponse = await api.get(`/api/tasks?deviceId=${device.deviceId}`);
            // const task = taskResponse.data[0]; // 每个设备对应一个任务

            const taskResponse = await getTaskList(device.deviceId);
            const task = taskResponse[0]; // 每个设备对应一个任务

            return {
                ...device,
                status: task ? task.status : '未实验',
                endTime: task ? task.endTime : '',
            };
        });

        const reportsWithTaskInfo = await Promise.all(tasksPromises);

        reportList.value = reportsWithTaskInfo;
        // 初始化过滤列表
        filteredReportList.value = reportsWithTaskInfo;
        total.value = reportList.value.length;
    } catch (error) {
        console.error('获取报表列表失败', error);
    } finally {
        loading.value = false;
    }
};

// 分页展示列表
const paginatedReportList = computed(() => {
    const start = (currentPage.value - 1) * pageSize.value;
    const end = start + pageSize.value;
    return filteredReportList.value.slice(start, end);
});

// 查看报表
const viewReport = async row => {
    try {
        // 获取组合报表数据
        // const response = await api.get(`/api/reports/${row.deviceId}`);
        // console.log("views:", response.data);
        // viewReportInfo.value = response.data;

        viewReportInfo.value = await getReport(row.deviceId);
        isViewVisible.value = true;
    } catch (error) {
        console.error('查看报表失败', error);
    }
};

const printReport = async row => {
    try {
        // const { data: reportData } = await api.get(`/api/reports/${row.deviceId}`);

        const reportData = await getReport(row.deviceId);
        const doc = new jsPDF();

        // 设置字体
        doc.setFont('SourceHanSansCN-Normal');

        // 页面布局参数
        const startX = 20; // 左侧起始位置
        const colWidth = 60; // 每列宽度
        const rowHeight = 10; // 行高
        let startY = 20; // 初始Y坐标

        // 添加标题
        doc.setFontSize(18).text('设备检测报表', 80, startY);
        startY += 20;

        // 设备信息
        doc.setFontSize(16).text('设备信息', startX, startY);
        startY += 10;
        doc.setFontSize(12);

        const deviceInfo = [
            [
                `设备ID: ${reportData.deviceInfo.deviceId}`,
                `设备名称: ${reportData.deviceInfo.deviceName}`,
                `设备型号: ${reportData.deviceInfo.deviceModel}`,
            ],
            [
                `生产日期: ${formatDate(reportData.deviceInfo.manufactureDate)}`,
                `送检日期: ${formatDate(reportData.deviceInfo.inspectionDate)}`,
                `制造商: ${reportData.deviceInfo.manufacturer}`,
            ],
        ];

        deviceInfo.forEach(row => {
            row.forEach((text, i) => {
                doc.text(text, startX + i * colWidth, startY);
            });
            startY += rowHeight;
        });

        startY += 10; // 间距

        // 遍历实验项目
        reportData.itemList.forEach((item, index) => {
            doc.setFontSize(16).text(`实验项目 ${index + 1}`, startX, startY);
            startY += 10;
            doc.setFontSize(12);

            // 任务信息 (每行3个)
            doc.setFontSize(14).text('项目信息', startX, startY);
            startY += 10;
            const taskInfo = [
                [
                    `检测项目ID: ${item.item_id}`,
                    `项目名称: ${item.project}`,
                    `档位: ${item.gear}`,
                ],
                [
                    `百分比: ${item.percentage}`,
                    `数据下限（%）: ${item.data_lower_limit}`,
                    `数据上限（%）: ${item.data_upper_limit}`,
                ],
            ];

            taskInfo.forEach(row => {
                row.forEach((text, i) => {
                    doc.text(text, startX + i * colWidth, startY);
                });
                startY += rowHeight;
            });

            startY += 10; // 间距

            // 结果信息 (每行3个)
            if (reportData.resultList[index]) {
                doc.setFontSize(14).text('结果信息', startX, startY);
                startY += 10;
                doc.setFontSize(12);

                const result = reportData.resultList[index];
                const resultInfo = [
                    [
                        `二次电压（U）: ${result.twoP}`,
                        `tanψ: ${result.tanValue}`,
                        `计量点编号: ${result.measuredId}`,
                    ],
                    [
                        `温度: ${result.temperature}`,
                        `湿度: ${result.humidity}`,
                        `测试日期: ${formatDate(result.testDate)}`,
                    ],
                    [
                        `fa: ${result.fa}`,
                        `fb: ${result.fb}`,
                        `fc: ${result.fc}`,
                    ],
                    [
                        `da: ${result.da}`,
                        `db: ${result.db}`,
                        `dc: ${result.dc}`,
                    ],
                    [
                        `dUa: ${result.dUa}`,
                        `dUb: ${result.dUb}`,
                        `dUc: ${result.dUc}`,
                    ],
                    [
                        `Upta: ${result.Upta}`,
                        `Uptb: ${result.Uptb}`,
                        `Uptc: ${result.Uptc}`,
                    ],
                    [
                        `Uyba: ${result.Uyba}`,
                        `Uybb: ${result.Uybb}`,
                        `Uybc: ${result.Uybc}`,
                    ],
                    [
                        `res1: ${result.res1}`,
                        `res2: ${result.res2}`,
                        `res3: ${result.res3}`,
                    ],
                    [`r%: ${result.rate}`],
                ];

                resultInfo.forEach(row => {
                    row.forEach((text, i) => {
                        if (startY > 250) {
                            doc.addPage();
                            startY = 20;
                        }
                        doc.text(text, startX + i * colWidth, startY);
                    });
                    startY += rowHeight;
                });

                startY += 10; // 间距
            }

            if (startY > 250) {
                doc.addPage();
                startY = 20;
            }
        });

        // 保存PDF
        doc.save(`设备_${row.deviceId}_报表.pdf`);
    } catch (error) {
        console.error('生成PDF失败', error);
    }
};

const handleSelectionChange = rows => {
    selectedRows.value = rows;
    isIndeterminate.value =
        rows.length > 0 && rows.length < paginatedReportList.value.length;
    if (rows.length === paginatedReportList.value.length) {
        isIndeterminate.value = false;
    }
};

const handleSelectAll = selection => {
    if (selection.length === paginatedReportList.value.length) {
        isIndeterminate.value = false;
    } else if (selection.length > 0) {
        isIndeterminate.value = true;
    } else {
        isIndeterminate.value = false;
    }
    selectedRows.value = selection;
};

const selectable = () => true;

// 搜索报表方法
const searchReports = () => {
    // 根据 searchDeviceId 过滤 reportList
    if (searchDeviceId.value) {
        filteredReportList.value = reportList.value.filter(report =>
            report.deviceId.includes(searchDeviceId.value)
        );
    } else {
        filteredReportList.value = reportList.value; // 如果搜索框为空，显示所有数据
    }

    total.value = filteredReportList.value.length; // 更新总条数
    currentPage.value = 1; // 重置页码
};

// 分页大小改变时的回调
const handleSizeChange = newSize => {
    pageSize.value = newSize;
    currentPage.value = 1;
};

// 当前页码改变时的回调
const handleCurrentChange = newPage => {
    currentPage.value = newPage;
};

// 初始化时获取报表列表
onMounted(() => {
    fetchReports();
});
</script>

<style lang="less" scoped>
@import url('@/views/list_share.less');

.disabled-link {
    color: #ccc;
    cursor: not-allowed;
}
</style>
