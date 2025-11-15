<template>
    <div
        v-if="isAddVisible"
        :key="uniqueKey"
        class="modal-overlay"
        style="z-index: 99"
        @click.self="closeModal"
    >
        <div class="modal">
            <div class="modal-header">
                <span>添加检测项目</span>
                <button @click="closeModal">×</button>
            </div>
            <div class="modal-content">
                <form>
                    <!-- 新增关联设备编号 -->
                    <div class="form-item">
                        <label>关联设备编号:</label>
                        <span>{{ deviceId }}</span>
                    </div>
                    <div class="form-item">
                        <label>*项目</label>
                        <el-select
                            v-model="itemInfo.project"
                            placeholder="请选择项目"
                            @change="handleProjectChange"
                        >
                            <el-option label="PT1" value="PT1" />
                            <el-option label="PT2" value="PT2" />
                            <el-option label="CT1" value="CT1" />
                            <el-option label="CT2" value="CT2" />
                        </el-select>
                    </div>
                    <div class="form-item">
                        <label>*档位</label>
                        <el-input
                            v-model="itemInfo.gearValue"
                            placeholder="请输入档位数值"
                            style="width: 350px; margin-right: 10px"
                        />
                        <el-select
                            v-model="itemInfo.gearUnit"
                            placeholder="档位单位"
                            :options="gearUnitOptions"
                            style="width: 200px"
                        />
                    </div>
                    <div class="form-item">
                        <label>*百分比(%)</label>
                        <el-input
                            v-model="itemInfo.percentage"
                            placeholder="请输入百分比"
                        />
                    </div>
                    <div class="form-item">
                        <label>*数据下限(%)</label>
                        <el-input
                            v-model="itemInfo.data_lower_limit"
                            placeholder="请输入数据下限"
                        />
                    </div>
                    <div class="form-item">
                        <label>*数据上限(%)</label>
                        <el-input
                            v-model="itemInfo.data_upper_limit"
                            placeholder="请输入数据上限"
                        />
                    </div>
                    <div class="form-item">
                        <label>*实测数据(%)</label>
                        <el-input
                            v-model="itemInfo.measured_data"
                            placeholder="请输入实测数据"
                        />
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <el-button type="primary" @click="saveItem"> 保存 </el-button>
                <el-button @click="resetForm"> 重置 </el-button>
            </div>
        </div>
    </div>
</template>

<script setup>
import { defineProps, defineEmits, ref } from 'vue';
import { add_inspectionItem } from '@/api/request.js';
import { ElMessage } from 'element-plus';

const props = defineProps({
    isAddVisible: {
        type: Boolean,
        default: false,
    },
    deviceId: {
        type: String,
        default: '',
    },
    taskId: {
        type: String,
        default: '',
    },
});

const emits = defineEmits(['close', 'refresh']);
const closeModal = () => {
    emits('close');
};

const itemInfo = ref({
    project: '',
    gearValue: '',
    gearUnit: '',
    percentage: null,
    data_lower_limit: null,
    data_upper_limit: null,
    measured_data: null,
});

const gearUnitOptions = ref([]);
const uniqueKey = ref(Date.now()); // 新增唯一key

const handleProjectChange = () => {
    if (itemInfo.value.project.startsWith('PT')) {
        gearUnitOptions.value = [{ label: 'V', value: 'V' }];
        itemInfo.value.gearUnit = 'V';
    } else if (itemInfo.value.project.startsWith('CT')) {
        gearUnitOptions.value = [{ label: 'A', value: 'A' }];
        itemInfo.value.gearUnit = 'A';
    } else {
        gearUnitOptions.value = [];
        itemInfo.value.gearUnit = '';
    }
};

const validateData = () => {
    const {
        project,
        gearValue,
        gearUnit,
        percentage,
        data_lower_limit,
        data_upper_limit,
        measured_data,
    } = itemInfo.value;
    if (
        !project ||
        !gearValue ||
        !gearUnit ||
        percentage === null ||
        data_lower_limit === null ||
        data_upper_limit === null ||
        measured_data === null
    ) {
        ElMessage.error('所有输入数据都不能为空');
        return false;
    }

    const numFields = [
        percentage,
        data_lower_limit,
        data_upper_limit,
        measured_data,
        parseFloat(gearValue),
    ];
    for (const num of numFields) {
        // 检查是否为有效的数字
        if (isNaN(parseFloat(num)) || !isFinite(num)) {
            ElMessage.error('所有输入的数值数据必须是有效的数字');
            return false;
        }
        // 检查是否为非负数
        if (num < 0) {
            ElMessage.error('所有输入的数值数据必须是非负数');
            return false;
        }
    }
    return true;
};

const saveItem = async () => {
    if (!validateData()) return;
    itemInfo.value.task_id = props.taskId;
    itemInfo.value.gear = `${itemInfo.value.gearValue}${itemInfo.value.gearUnit}`;

    try {
        await add_inspectionItem(itemInfo.value);
        closeModal();
        emits('refresh');
        resetForm();
    } catch (error) {
        console.error('保存检测项目信息失败', error);
    }
};

const resetForm = () => {
    itemInfo.value = {
        project: '',
        gearValue: '',
        gearUnit: '',
        percentage: null,
        data_lower_limit: null,
        data_upper_limit: null,
        measured_data: null,
    };
    gearUnitOptions.value = [];
    uniqueKey.value = Date.now(); // 重置key
};

handleProjectChange();
</script>

<style scoped>
@import url('@/views/modal.less');
</style>
// await api.post('/api/inspection_items', itemInfo.value);
