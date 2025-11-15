<template>
    <div
        v-if="isViewVisible"
        class="modal-overlay"
        style="z-index: 99"
        @click.self="closeModal"
    >
        <div class="modal">
            <div class="modal-header">
                <span>结果详情</span>
                <button @click="closeModal">×</button>
            </div>
            <div class="modal-content">
                <el-form :model="resultInfo" label-width="150px">
                    <el-row :gutter="20">
                        <el-col :span="8">
                            <el-form-item label="关联设备编号：">
                                <span>{{ resultInfo.deviceId }}</span>
                            </el-form-item>
                        </el-col>
                        <el-col :span="8">
                            <el-form-item label="二次电压（U）：">
                                <span>{{ resultInfo.twoP }}</span>
                            </el-form-item>
                        </el-col>
                        <el-col :span="8">
                            <el-form-item label="tanψ：">
                                <span>{{ resultInfo.tanValue }}</span>
                            </el-form-item>
                        </el-col>
                    </el-row>

                    <el-row :gutter="20">
                        <el-col :span="8">
                            <el-form-item label="计量点编号：">
                                <span>{{ resultInfo.measuredId }}</span>
                            </el-form-item>
                        </el-col>
                        <el-col :span="8">
                            <el-form-item label="温度：">
                                <span>{{ resultInfo.temperature }}</span>
                            </el-form-item>
                        </el-col>
                        <el-col :span="8">
                            <el-form-item label="湿度：">
                                <span>{{ resultInfo.humidity }}</span>
                            </el-form-item>
                        </el-col>
                    </el-row>

                    <el-row :gutter="20">
                        <el-col :span="8">
                            <el-form-item label="测试日期：">
                                <span>{{
                                    format(resultInfo.testDate, 'yyyy-MM-dd')
                                }}</span>
                            </el-form-item>
                        </el-col>
                        <el-col :span="8">
                            <el-form-item label="fa：">
                                <span>{{ resultInfo.fa }}</span>
                            </el-form-item>
                        </el-col>
                        <el-col :span="8">
                            <el-form-item label="fb：">
                                <span>{{ resultInfo.fb }}</span>
                            </el-form-item>
                        </el-col>
                    </el-row>

                    <el-row :gutter="20">
                        <el-col :span="8">
                            <el-form-item label="fc：">
                                <span>{{ resultInfo.fc }}</span>
                            </el-form-item>
                        </el-col>
                        <el-col :span="8">
                            <el-form-item label="da：">
                                <span>{{ resultInfo.da }}</span>
                            </el-form-item>
                        </el-col>
                        <el-col :span="8">
                            <el-form-item label="db：">
                                <span>{{ resultInfo.db }}</span>
                            </el-form-item>
                        </el-col>
                    </el-row>

                    <el-row :gutter="20">
                        <el-col :span="8">
                            <el-form-item label="dc：">
                                <span>{{ resultInfo.dc }}</span>
                            </el-form-item>
                        </el-col>
                        <el-col :span="8">
                            <el-form-item label="dUa：">
                                <span>{{ resultInfo.dUa }}</span>
                            </el-form-item>
                        </el-col>
                        <el-col :span="8">
                            <el-form-item label="dUb：">
                                <span>{{ resultInfo.dUb }}</span>
                            </el-form-item>
                        </el-col>
                    </el-row>

                    <el-row :gutter="20">
                        <el-col :span="8">
                            <el-form-item label="dUc：">
                                <span>{{ resultInfo.dUc }}</span>
                            </el-form-item>
                        </el-col>
                        <el-col :span="8">
                            <el-form-item label="Upta：">
                                <span>{{ resultInfo.Upta }}</span>
                            </el-form-item>
                        </el-col>
                        <el-col :span="8">
                            <el-form-item label="Uptb：">
                                <span>{{ resultInfo.Uptb }}</span>
                            </el-form-item>
                        </el-col>
                    </el-row>

                    <el-row :gutter="20">
                        <el-col :span="8">
                            <el-form-item label="Uptc：">
                                <span>{{ resultInfo.Uptc }}</span>
                            </el-form-item>
                        </el-col>
                        <el-col :span="8">
                            <el-form-item label="Uyba：">
                                <span>{{ resultInfo.Uyba }}</span>
                            </el-form-item>
                        </el-col>
                        <el-col :span="8">
                            <el-form-item label="Uybb：">
                                <span>{{ resultInfo.Uybb }}</span>
                            </el-form-item>
                        </el-col>
                    </el-row>

                    <el-row :gutter="20">
                        <el-col :span="8">
                            <el-form-item label="Uybc：">
                                <span>{{ resultInfo.Uybc }}</span>
                            </el-form-item>
                        </el-col>
                        <el-col :span="8">
                            <el-form-item label="r%：">
                                <span>{{ resultInfo.rate }}</span>
                            </el-form-item>
                        </el-col>
                        <el-col :span="8">
                            <el-form-item label="res1：">
                                <span>{{ resultInfo.res1 }}</span>
                            </el-form-item>
                        </el-col>
                    </el-row>

                    <el-row :gutter="20">
                        <el-col :span="8">
                            <el-form-item label="res2：">
                                <span>{{ resultInfo.res2 }}</span>
                            </el-form-item>
                        </el-col>
                        <el-col :span="8">
                            <el-form-item label="res3：">
                                <span>{{ resultInfo.res3 }}</span>
                            </el-form-item>
                        </el-col>
                        <el-col :span="8">
                            <el-form-item label="res4：">
                                <span>{{ resultInfo.res4 }}</span>
                            </el-form-item>
                        </el-col>
                    </el-row>
                </el-form>
            </div>
            <!-- <div class="image-container">
        <el-button @click="showImage">查看实验结果图像</el-button>
        <img v-if="showingImage" :src="imageUrl" alt="实验结果图像" style="max-width: 300px; max-height: 300px;">
      </div> -->
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
    resultInfo: {
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

.modal {
    width: 1000px;
    max-height: 90vh;
    overflow-y: auto;
}
</style>
