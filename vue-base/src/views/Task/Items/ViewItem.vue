<template>
    <div
        v-if="isViewVisible"
        class="modal-overlay"
        style="z-index: 99"
        @click.self="closeModal"
    >
        <div class="modal">
            <div class="modal-header">
                <span>查看检测项目详情</span>
                <button @click="closeModal">×</button>
            </div>
            <div class="modal-content">
                <div class="form-item">
                    <label>检测项目ID:</label>
                    <span>{{ itemInfo.item_id }}</span>
                </div>
                <div class="form-item">
                    <label>项目:</label>
                    <span>{{ itemInfo.project }}</span>
                </div>
                <div class="form-item">
                    <label>档位:</label>
                    <span>{{ itemInfo.gear }}</span>
                </div>
                <div class="form-item">
                    <label>百分比(%):</label>
                    <span>{{ itemInfo.percentage }}</span>
                </div>
                <div class="form-item">
                    <label>数据下限(%):</label>
                    <span>{{ itemInfo.data_lower_limit }}</span>
                </div>
                <div class="form-item">
                    <label>数据上限(%):</label>
                    <span>{{ itemInfo.data_upper_limit }}</span>
                </div>
                <div class="form-item">
                    <label>实测数据(%):</label>
                    <span>{{ itemInfo.measured_data }}</span>
                </div>
                <div class="form-item">
                    <label>关联任务ID:</label>
                    <span>{{ itemInfo.task_id }}</span>
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

const props = defineProps({
    itemInfo: {
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
</script>

<style scoped>
@import url('@/views/modal.less');
</style>
