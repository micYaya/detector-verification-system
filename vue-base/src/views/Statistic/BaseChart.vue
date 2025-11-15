<template>
    <!-- 图表容器 div，绑定 ref -->
    <div ref="chartRef" :style="style" />
</template>

<script setup>
// 引入 Vue 的响应式和生命周期方法
import { ref, onMounted, watch, onBeforeUnmount } from 'vue';
import { useDebounceFn } from '@vueuse/core'; // 防抖函数

// 按需引入 ECharts 核心和组件
import * as echarts from 'echarts/core';
import { PieChart, LineChart } from 'echarts/charts'; // 支持的图表类型
import {
    TitleComponent,
    TooltipComponent,
    LegendComponent,
    GridComponent,
} from 'echarts/components'; // 图表常用组件（标题、提示框、图例、网格等）
import { CanvasRenderer } from 'echarts/renderers'; // 渲染器：使用 Canvas

// 注册需要用到的 ECharts 模块（按需引入）
echarts.use([
    PieChart,
    LineChart,
    TitleComponent,
    TooltipComponent,
    LegendComponent,
    GridComponent,
    CanvasRenderer,
]);

// 接收外部传入的 props：图表配置项和样式
const props = defineProps({
    option: Object,

    // 图表容器的样式
    style: {
        type: Object,
        default: () => ({
            width: '100%',
            height: '400px',
        }),
    },
});

// 图表容器的 DOM 引用
const chartRef = ref(null);

// ECharts 实例
let chartInstance = null;

// 初始化图表函数
const initChart = () => {
    if (!chartRef.value) return;

    // 初始化 ECharts 实例
    chartInstance = echarts.init(chartRef.value);

    // 设置图表配置
    if (props.option) {
        // 设置响应式
        props.option.responsive = true;
        // 应用配置
        chartInstance.setOption(props.option);
    }
};

// 调整图标尺寸
const resizeChart = () => {
    if (chartInstance) {
        chartInstance.resize();
    }
};

// 防抖，延迟300ms触发resize
const debouncedResize = useDebounceFn(resizeChart, 300);

// 初始化时执行一次
onMounted(() => {
    initChart();
    window.addEventListener('resize', debouncedResize);
});

// 监听 props.option 变化，动态更新图表
watch(
    () => props.option,
    newVal => {
        if (chartInstance && newVal) {
            newVal.responsive = true;
            chartInstance.setOption(newVal);
        }
    },
    { deep: true }
);
// 启动深度监听，递归监听内部所有层级的属性变化

// 页面卸载时销毁图表实例，防止内存泄漏
onBeforeUnmount(() => {
    if (chartInstance) {
        chartInstance.dispose();
        chartInstance = null;
    }
    // 移除监听函数
    window.removeEventListener('resize', debouncedResize);
});
</script>
