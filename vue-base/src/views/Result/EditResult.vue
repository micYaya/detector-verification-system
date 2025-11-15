<template>
    <div
        v-if="isEditVisible"
        class="modal-overlay"
        style="z-index: 99"
        @click.self="closeModal"
    >
        <div class="modal">
            <div class="modal-header">
                <span>编辑结果</span>
                <button @click="closeModal">×</button>
            </div>
            <div class="modal-content">
                <ResultForm :result-info="resultInfo" />
            </div>
            <div class="modal-footer">
                <el-button type="primary" @click="saveResult"> 保存 </el-button>
                <el-button @click="resetForm"> 重置 </el-button>
            </div>
        </div>
    </div>
</template>

<script setup>
import { defineProps, defineEmits } from 'vue';
import { edit_result } from '@/api/request.js';
import { format } from 'date-fns';
import ResultForm from './components/ResultForm.vue';

const props = defineProps({
    resultInfo: {
        type: Object,
        default: () => ({}),
    },
    isEditVisible: {
        type: Boolean,
        default: false,
    },
});
const emits = defineEmits(['close', 'refresh']);
const saveResult = async () => {
    if (props.resultInfo.testDate) {
        props.resultInfo.testDate = format(
            props.resultInfo.testDate,
            'yyyy-MM-dd'
        );
    }

    console.log('要发送的数据:', props.resultInfo); // 输出要发送的数据

    try {
        // await api.put(`/api/results/${props.resultInfo.resultId}`, props.resultInfo);
        await edit_result(props.resultInfo.resultId, props.resultInfo);
        emits('refresh');
        emits('close');
        // resetForm();
    } catch (error) {
        console.error('保存结果失败:', error);
    }
};

const closeModal = () => {
    emits('close');
};
</script>

<style scoped>
@import url('@/views/modal.less');

.modal {
    width: 1000px;
    max-height: 90vh;
    overflow-y: auto;
}
</style>
