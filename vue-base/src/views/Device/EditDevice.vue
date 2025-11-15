<template>
    <div
        v-if="isEditVisible"
        class="modal-overlay"
        style="z-index: 99"
        @click.self="closeModal"
    >
        <div class="modal">
            <div class="modal-header">
                <span>编辑设备信息</span>
                <button @click="closeModal">×</button>
            </div>
            <div class="modal-content">
                <DeviceForm ref="formRef" :device-info="deviceInfo" />
            </div>
            <div class="modal-footer">
                <el-button type="primary" @click="saveDevice"> 保存 </el-button>
                <!-- 绑定保存事件 -->
                <el-button @click="closeModal"> 取消 </el-button>
            </div>
        </div>
    </div>
</template>

<script setup>
import { defineProps, defineEmits, ref } from 'vue';
import { format } from 'date-fns';
import { edit_device } from '@/api/request.js';
import DeviceForm from './components/DeviceForm.vue';
import { ElMessage } from 'element-plus';

const props = defineProps({
    deviceInfo: {
        type: Object,
        default: () => ({}),
    },
    isEditVisible: {
        type: Boolean,
        default: false,
    },
});

const emits = defineEmits(['close', 'refresh']); // 增加refresh事件通知父组件刷新

const closeModal = () => {
    emits('close');
};

const formRef = ref(null);

// 处理日期格式并保存
const saveDevice = async () => {
    formRef.value.formRef.validate(async valid => {
        if (valid) {
            if (props.deviceInfo.id) {
                if (props.deviceInfo.manufactureDate) {
                    props.deviceInfo.manufactureDate = format(
                        props.deviceInfo.manufactureDate,
                        'yyyy-MM-dd HH:mm:ss'
                    );
                }
                if (props.deviceInfo.inspectionDate) {
                    props.deviceInfo.inspectionDate = format(
                        props.deviceInfo.inspectionDate,
                        'yyyy-MM-dd HH:mm:ss'
                    );
                }

                try {
                    await edit_device(props.deviceInfo);
                    emits('close');
                    emits('refresh');
                } catch (error) {
                    console.error('编辑设备信息失败', error);
                }
            }
        } else {
            ElMessage.error('表单验证不通过，请检查输入信息');
            // console.log('验证不通过');
            return false;
        }
    });
};
</script>

<style scoped>
@import url('@/views/modal.less');
</style>
