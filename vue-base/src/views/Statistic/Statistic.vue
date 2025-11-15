<template>
    <!-- 面包屑导航 -->
    <el-breadcrumb separator="/" class="breadcrumb">
        <el-breadcrumb-item>首页</el-breadcrumb-item>
        <el-breadcrumb-item>统计与分析</el-breadcrumb-item>
    </el-breadcrumb>
    <div class="statistic-page">
        <div class="statistic-card-container">
            <div
                v-for="(count, key) in statisticCounts"
                :key="key"
                class="statistic-card"
            >
                <span class="count-label">{{ keyLabel[key] }}</span>
                <span class="count-number">{{ count }}</span>
            </div>
        </div>

        <div class="chart-container">
            <div class="chart-item-shadow">
                <h3 class="chart-title">已完成任务设备占比</h3>
                <BaseChart :option="ringChartOption" />
            </div>
            <div class="chart-item-shadow">
                <h3 class="chart-title">近一个月送检设备数量</h3>
                <BaseChart :option="lineChartOption" />
            </div>
            <div class="chart-item-shadow">
                <h3 class="chart-title">实验项目分类统计</h3>
                <BaseChart :option="pieChartOption" />
            </div>
        </div>
    </div>
</template>

<script setup>
import { ref, onMounted } from 'vue';
import dayjs from 'dayjs';
import {
    getDeviceList,
    getTasks,
    getInspectionItems,
    getResults,
    getDevicesMonth,
} from '@/api/request.js';
import BaseChart from './BaseChart.vue';

// 统计数据
const statisticCounts = ref({
    device: 0,
    task: 0,
    item: 0,
    result: 0,
});

const keyLabel = {
    device: '设备数量',
    task: '任务数量',
    item: '实验项目数量',
    result: '结果数量',
};

// 环图数据
const completedDeviceRatio = ref(0);
// 折线图数据
const dailyInspectionData = ref([]);
// 饼图数据
const projectCategoryData = ref([]);

const ringChartOption = ref({});
const lineChartOption = ref({});
const pieChartOption = ref({});

// 获取统计数据
const fetchStatistics = async () => {
    try {
        // 异步请求并行化，优化加载时间
        const [deviceRes, taskRes, itemRes, resultRes] = await Promise.all([
            getDeviceList(),
            getTasks(),
            getInspectionItems(),
            getResults(),
        ]);

        // 设备数量
        statisticCounts.value.device = deviceRes.length;
        // 任务数量
        statisticCounts.value.task = taskRes.length;
        // 实验项目数量
        statisticCounts.value.item = itemRes.length;
        // 结果数量
        statisticCounts.value.result = resultRes.length;

        // 已完成任务设备占比
        const completedTasks = taskRes.filter(task => task.status === '已完成');
        completedDeviceRatio.value =
            (completedTasks.length / deviceRes.length) * 100;

        // 近一个月送检设备统计
        const now = dayjs();
        const oneMonthAgo = now.subtract(1, 'month').format('YYYY-MM-DD');
        const inspectionRes = await getDevicesMonth(oneMonthAgo);
        const dailyData = {};
        inspectionRes.forEach(device => {
            const date = dayjs(device.inspectionDate).format('YYYY-MM-DD');
            dailyData[date] = (dailyData[date] || 0) + 1;
        });
        dailyInspectionData.value = Object.entries(dailyData).map(
            ([date, count]) => ({
                date,
                count,
            })
        );

        // 实验项目分类统计
        const projectMap = new Map();
        itemRes.forEach(item => {
            projectMap.set(
                item.project,
                (projectMap.get(item.project) || 0) + 1
            );
        });
        projectCategoryData.value = Array.from(projectMap.entries()).map(
            ([project, count]) => ({
                value: count,
                name: project,
            })
        );

        // 设置图表配置项
        ringChartOption.value = {
            title: { text: '已完成任务设备占比', left: 'center' },
            series: [
                {
                    type: 'pie',
                    radius: ['50%', '70%'],
                    label: {
                        formatter: `${completedDeviceRatio.value.toFixed(1)}%`,
                        fontSize: '3rem',
                        position: 'center',
                    },
                    data: [
                        {
                            value: completedDeviceRatio.value,
                            name: '已完成任务设备',
                        },
                        {
                            value: 100 - completedDeviceRatio.value,
                            name: '未完成任务设备',
                        },
                    ],
                },
            ],
        };

        lineChartOption.value = {
            title: { text: '近一个月送检设备数量', left: 'center' },
            xAxis: { data: dailyInspectionData.value.map(item => item.date) },
            yAxis: {},
            series: [
                {
                    data: dailyInspectionData.value.map(item => item.count),
                    type: 'line',
                },
            ],
            tooltip: {
                // trigger: 'axis',
                show: true,
            },
        };

        pieChartOption.value = {
            title: { text: '实验项目分类统计', left: 'center' },
            series: [
                {
                    type: 'pie',
                    data: projectCategoryData.value,
                },
            ],
            tooltip: {
                // trigger: 'item',
                show: true,
            },
        };
    } catch (error) {
        console.error('获取统计数据失败', error);
    }
};

onMounted(() => {
    fetchStatistics();
});
</script>

<style scoped>
.statistic-page {
    padding: 20px;
}

.statistic-card-container {
    display: flex;
    gap: 3vw;
    margin-bottom: 30px;
}

.statistic-card {
    width: 20vw;
    height: 5vw;
    font-size: 2.2vw;
    background: #fff;
    padding: 1vw;
    border-radius: 0.5vw;
    display: flex;
    align-items: center;
    gap: 0.5vw;
}

.count-number {
    font-size: 2.5vw;
    font-weight: bold;
}

.count-label {
    color: #666;
}

.chart-container {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 20px;
}

.chart-item-shadow {
    padding: 20px;
    box-shadow: 0 0 10px rgb(0 0 0 / 10%);
    border-radius: 8px;
    display: grid;
    align-items: center;
}

.chart-title {
    margin-top: 0;
    color: #333;
    border-bottom: 1px solid #eee;
    padding-bottom: 10px;
    margin-bottom: 15px;
}

@media screen and (width <= 1300px) and (width >= 600px) {
    .statistic-card-container {
        /* 两列布局 */
        display: grid;
        grid-template-columns: repeat(2, 1fr);
    }

    .statistic-card {
        width: auto;
        height: 75px;
        font-size: 3vw;
    }

    .chart-container {
        /* 图表是单列布局 */
        grid-template-columns: 1fr;
        justify-items: center;
    }

    .chart-item-shadow {
        width: 80%;
        left: 0;
    }
}

@media screen and (width <= 600px) {
    .statistic-card-container {
        margin-right: 18px;
        flex-direction: column;
    }

    .statistic-card {
        width: 100%;
        height: 75px;
        padding: 1vw;
        margin-bottom: 10px;
        font-size: 6vw;
    }

    .count-number {
        font-size: 6vw;
    }

    .chart-container {
        grid-template-columns: 1fr;
        justify-items: center;
    }

    .chart-item-shadow {
        width: 80%;
        left: 0;
    }
}
</style>
