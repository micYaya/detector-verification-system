<template>
    <div
        v-if="isAddVisible"
        class="modal-overlay"
        style="z-index: 99"
        @click.self="closeModal"
    >
        <div class="modal">
            <div class="modal-header">
                <span>添加设备</span>
                <button @click="closeModal">×</button>
            </div>
            <div class="modal-content">
                <DeviceForm ref="formRef" :device-info="deviceInfo" />
            </div>
            <div class="modal-footer">
                <el-button type="primary" @click="saveDevice"> 保存 </el-button>
                <el-button @click="resetForm"> 重置 </el-button>
            </div>
        </div>
    </div>
</template>

<script setup>
import { defineProps, defineEmits, ref } from 'vue';
import { format } from 'date-fns';
import { checkDeviceExists, add_device } from '@/api/request.js';
import DeviceForm from './components/DeviceForm.vue';
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

const deviceInfo = ref({
    deviceId: '',
    deviceName: '',
    deviceModel: '',
    manufactureDate: null,
    inspectionDate: null,
    manufacturer: '',
    productionPlace: '',
    deviceStatus: '',
});

const formRef = ref(null);

const saveDevice = async () => {
    formRef.value.formRef.validate(async valid => {
        if (valid) {
            if (
                deviceInfo.value.manufactureDate &&
                deviceInfo.value.inspectionDate
            ) {
                deviceInfo.value.manufactureDate = format(
                    deviceInfo.value.manufactureDate,
                    'yyyy-MM-dd HH:mm:ss'
                );
                deviceInfo.value.inspectionDate = format(
                    deviceInfo.value.inspectionDate,
                    'yyyy-MM-dd HH:mm:ss'
                );
            }

            try {
                const deviceExist = await checkDeviceExists(
                    deviceInfo.value.deviceId
                );
                console.log(deviceExist.exist);
                if (deviceExist.exist !== 0) {
                    ElMessage.error('该设备编号已存在，请重新输入设备编号');
                    return;
                }
                await add_device(deviceInfo.value);
                closeModal();
                emits('refresh');
                resetForm();
            } catch (error) {
                console.error('保存设备信息失败', error);
            }
        } else {
            ElMessage.error('表单验证不通过，请检查输入信息');
            // console.log('验证不通过');
            return false;
        }
    });
};

const resetForm = () => {
    deviceInfo.value = {
        deviceId: '',
        deviceName: '',
        deviceModel: '',
        manufactureDate: null,
        inspectionDate: null,
        manufacturer: '',
        productionPlace: '',
        deviceStatus: '',
    };
    formRef.value.formRef.resetFields();
};
</script>

<style scoped>
@import url('@/views/modal.less');
</style>
