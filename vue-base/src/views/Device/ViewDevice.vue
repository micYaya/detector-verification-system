<template>
    <div
        v-if="isViewVisible"
        class="modal-overlay"
        style="z-index: 99"
        @click.self="closeModal"
    >
        <div class="modal">
            <div class="modal-header">
                <span>查看详情</span>
                <button @click="closeModal">×</button>
            </div>
            <div class="modal-content">
                <div class="form-item">
                    <label>设备ID:</label>
                    <span>{{ deviceInfo.deviceId }}</span>
                </div>
                <div class="form-item">
                    <label>设备名称:</label>
                    <span>{{ deviceInfo.deviceName }}</span>
                </div>
                <div class="form-item">
                    <label>设备型号:</label>
                    <span>{{ deviceInfo.deviceModel }}</span>
                </div>
                <div class="form-item">
                    <label>制造商:</label>
                    <span>{{ deviceInfo.manufacturer }}</span>
                </div>
                <div class="form-item">
                    <label>产地:</label>
                    <span>{{ deviceInfo.productionPlace }}</span>
                </div>
                <div class="form-item">
                    <label>生产日期:</label>
                    <!-- 使用 formatDate 方法格式化日期 -->
                    <span>{{ formatDate(deviceInfo.manufactureDate) }}</span>
                </div>
                <div class="form-item">
                    <label>送检日期:</label>
                    <!-- 使用 formatDate 方法格式化日期 -->
                    <span>{{ formatDate(deviceInfo.inspectionDate) }}</span>
                </div>
                <div class="form-item">
                    <label>设备状态:</label>
                    <span>{{ deviceInfo.deviceStatus }}</span>
                </div>
            </div>
            <div class="modal-footer">
                <el-button @click="closeModal"> 关闭 </el-button>
            </div>
        </div>
    </div>
</template>

<script setup>
import { defineProps, defineEmits } from 'vue';
import { format } from 'date-fns';

const props = defineProps({
    deviceInfo: {
        type: Object,
        default: () => ({}),
    },
    isViewVisible: {
        type: Boolean,
        default: false,
    },
});

const emits = defineEmits(['close']);

const closeModal = () => {
    emits('close');
};

// 定义日期格式化方法
const formatDate = dateStr => {
    if (!dateStr) return '';
    return format(new Date(dateStr), 'yyyy-MM-dd HH:mm:ss');
};
</script>

<style scoped>
@import url('../modal.less');
</style>
