<template>
    <el-form ref="formRef" :model="deviceInfo" :rules="rules">
        <el-form-item label="设备ID" prop="deviceId">
            <el-input
                v-model="deviceInfo.deviceId"
                placeholder="请输入设备ID"
            />
        </el-form-item>
        <el-form-item label="设备名称" prop="deviceName">
            <el-input
                v-model="deviceInfo.deviceName"
                placeholder="请输入设备名称"
            />
        </el-form-item>
        <el-form-item label="设备型号" prop="deviceModel">
            <el-input
                v-model="deviceInfo.deviceModel"
                placeholder="请输入设备型号"
            />
        </el-form-item>
        <el-form-item label="生产日期" prop="manufactureDate">
            <el-date-picker
                v-model="deviceInfo.manufactureDate"
                type="datetime"
                placeholder="请选择生产日期"
                style="width: 240px"
            />
        </el-form-item>
        <el-form-item label="送检日期" prop="inspectionDate">
            <el-date-picker
                v-model="deviceInfo.inspectionDate"
                type="datetime"
                placeholder="请选择送检日期"
                style="width: 240px"
            />
        </el-form-item>
        <el-form-item label="制造商" prop="manufacturer">
            <el-input
                v-model="deviceInfo.manufacturer"
                placeholder="请输入制造商"
            />
        </el-form-item>
        <el-form-item label="产地" prop="productionPlace">
            <el-input
                v-model="deviceInfo.productionPlace"
                placeholder="请输入产地"
            />
        </el-form-item>
        <el-form-item label="设备状态" prop="deviceStatus">
            <el-radio-group v-model="deviceInfo.deviceStatus">
                <el-radio label="已检测"> 已检测 </el-radio>
                <el-radio label="未检测"> 未检测 </el-radio>
            </el-radio-group>
        </el-form-item>
    </el-form>
</template>

<script setup>
import { defineProps, ref, defineExpose } from 'vue';
import { validateID } from '@/utils/validators.js';

const props = defineProps({
    deviceInfo: {
        type: Object,
        default: () => ({}),
    },
});

const formRef = ref(null);

const rules = {
    deviceId: [
        { required: true, message: '请输入设备ID', trigger: 'blur' },
        { validator: validateID, message: '设备ID必须是数字', trigger: 'blur' },
    ],
    deviceName: [
        { required: true, message: '请输入设备名称', trigger: 'blur' },
        {
            min: 3,
            max: 10,
            message: '设备名称长度必须在3到10之间',
            trigger: 'blur',
        },
    ],
    deviceModel: [
        { required: true, message: '请输入设备型号', trigger: 'blur' },
        {
            min: 1,
            max: 10,
            message: '设备型号长度必须在1到10之间',
            trigger: 'blur',
        },
    ],
    manufacturer: [
        { required: true, message: '请输入制造商', trigger: 'blur' },
        {
            min: 3,
            max: 15,
            message: '制造商长度必须在3到15之间',
            trigger: 'blur',
        },
    ],
    productionPlace: [
        { required: true, message: '请输入产地', trigger: 'blur' },
        {
            min: 3,
            max: 15,
            message: '产地长度必须在3到15之间',
            trigger: 'blur',
        },
    ],
};

// 暴露表单实例给父组件（供父组件ref访问）
const expose = { formRef };
defineExpose(expose);
</script>

<style scoped></style>
