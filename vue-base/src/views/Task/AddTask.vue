<template>
    <div
        v-if="isAddVisible"
        class="modal-overlay"
        style="z-index: 99"
        @click.self="closeModal"
    >
        <div class="modal">
            <div class="modal-header">
                <span>添加任务</span>
                <button @click="closeModal">×</button>
            </div>
            <div class="modal-content">
                <form>
                    <div class="form-item">
                        <label>*设备编号</label>
                        <el-input
                            v-model="taskInfo.deviceId"
                            placeholder="请输入设备编号"
                            style="width: 300px"
                        />
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <el-button
                    type="primary"
                    :disabled="!taskInfo.deviceId"
                    @click="saveTask"
                >
                    保存
                </el-button>
                <el-button @click="resetForm"> 重置 </el-button>
            </div>
        </div>
    </div>
</template>

<script setup>
import { defineProps, defineEmits, ref } from 'vue';
import { checkDeviceExists, add_task } from '@/api/request.js';
import { ElMessage } from 'element-plus';

const props = defineProps({
    isAddVisible: {
        type: Boolean,
        default: false,
    },
});

const emits = defineEmits(['close', 'refresh']);
const closeModal = () => {
    emits('close');
};

const taskInfo = ref({
    deviceId: '',
    startTime: null,
    endTime: null,
    status: '未开始',
});

const resetForm = () => {
    taskInfo.value = {
        deviceId: '',
        startTime: null,
        endTime: null,
        status: '未开始',
    };
};

const saveTask = async () => {
    try {
        // 检查设备编号是否存在(.data与无.data)
        // const deviceResponse = await api.get(`/api/devices/${taskInfo.value.deviceId}`);
        const deviceResponse = await checkDeviceExists(taskInfo.value.deviceId);

        // 检查返回数据中的error字段
        if (deviceResponse.error) {
            ElMessage.error(deviceResponse.error);
            return;
        }

        // 设备存在时创建任务
        // const taskResponse = await api.post('/api/tasks', taskInfo.value);
        const taskResponse = await add_task(taskInfo.value);
        if (taskResponse && !taskResponse.error) {
            ElMessage.success('任务创建成功');
            resetForm();
            closeModal();
            emits('refresh');
        } else {
            ElMessage.error('任务创建失败，请检查参数');
        }
    } catch (error) {
        console.error('保存任务失败', error);
        ElMessage.error('保存任务失败，请稍后重试');
    }
};
</script>

<style scoped>
@import url('../modal.less');
</style>
