<template>
    <div
        v-if="isViewVisible"
        class="modal-overlay"
        style="z-index: 99"
        @click.self="closeModal"
    >
        <div class="modal">
            <div class="modal-header">
                <span>报表详情</span>
                <button @click="closeModal">×</button>
            </div>
            <div class="modal-content">
                <h2>设备信息</h2>
                <el-form :model="reportInfo.deviceInfo" label-width="150px">
                    <el-row :gutter="20">
                        <el-col :span="8">
                            <el-form-item label="设备ID：">
                                <span>{{
                                    reportInfo.deviceInfo.deviceId
                                }}</span>
                            </el-form-item>
                        </el-col>
                        <el-col :span="8">
                            <el-form-item label="设备名称：">
                                <span>{{
                                    reportInfo.deviceInfo.deviceName
                                }}</span>
                            </el-form-item>
                        </el-col>
                        <el-col :span="8">
                            <el-form-item label="设备型号：">
                                <span>{{
                                    reportInfo.deviceInfo.deviceModel
                                }}</span>
                            </el-form-item>
                        </el-col>
                        <el-col :span="8">
                            <el-form-item label="生产日期：">
                                <span>{{
                                    formatDate(
                                        reportInfo.deviceInfo.manufactureDate
                                    )
                                }}</span>
                            </el-form-item>
                        </el-col>
                        <el-col :span="8">
                            <el-form-item label="送检日期：">
                                <span>{{
                                    formatDate(
                                        reportInfo.deviceInfo.inspectionDate
                                    )
                                }}</span>
                            </el-form-item>
                        </el-col>
                        <el-col :span="8">
                            <el-form-item label="制造商：">
                                <span>{{
                                    reportInfo.deviceInfo.manufacturer
                                }}</span>
                            </el-form-item>
                        </el-col>
                    </el-row>
                    <!-- </el-form> -->

                    <h2>实验信息</h2>
                    <div
                        v-for="(item, index) in reportInfo.itemList"
                        :key="item.item_id"
                    >
                        <h3>实验项目 {{ index + 1 }}</h3>
                        <h4>项目信息</h4>
                        <el-row :gutter="20">
                            <el-col :span="8">
                                <el-form-item label="检测项目ID：">
                                    <span>{{ item.item_id }}</span>
                                </el-form-item>
                            </el-col>
                            <el-col :span="8">
                                <el-form-item label="项目名称：">
                                    <span>{{ item.project }}</span>
                                </el-form-item>
                            </el-col>
                            <el-col :span="8">
                                <el-form-item label="档位：">
                                    <span>{{ item.gear }}</span>
                                </el-form-item>
                            </el-col>
                            <el-col :span="8">
                                <el-form-item label="百分比：">
                                    <span>{{ item.percentage }}</span>
                                </el-form-item>
                            </el-col>
                            <el-col :span="8">
                                <el-form-item label="数据下限（%）：">
                                    <span>{{ item.data_lower_limit }}</span>
                                </el-form-item>
                            </el-col>
                            <el-col :span="8">
                                <el-form-item label="数据上限（%）：">
                                    <span>{{ item.data_upper_limit }}</span>
                                </el-form-item>
                            </el-col>
                        </el-row>

                        <div class="result-info">
                            <h4>结果信息</h4>
                            <el-row :gutter="20">
                                <el-col :span="8">
                                    <el-form-item label="二次电压（U）：">
                                        <span>{{
                                            reportInfo.resultList[index]?.twoP
                                        }}</span>
                                    </el-form-item>
                                </el-col>
                                <el-col :span="8">
                                    <el-form-item label="tanψ：">
                                        <span>{{
                                            reportInfo.resultList[index]
                                                ?.tanValue
                                        }}</span>
                                    </el-form-item>
                                </el-col>
                                <el-col :span="8">
                                    <el-form-item label="计量点编号：">
                                        <span>{{
                                            reportInfo.resultList[index]
                                                ?.measuredId
                                        }}</span>
                                    </el-form-item>
                                </el-col>
                                <el-col :span="8">
                                    <el-form-item label="温度：">
                                        <span>{{
                                            reportInfo.resultList[index]
                                                ?.temperature
                                        }}</span>
                                    </el-form-item>
                                </el-col>
                                <el-col :span="8">
                                    <el-form-item label="湿度：">
                                        <span>{{
                                            reportInfo.resultList[index]
                                                ?.humidity
                                        }}</span>
                                    </el-form-item>
                                </el-col>
                                <el-col :span="8">
                                    <el-form-item label="测试日期：">
                                        <span>{{
                                            format(
                                                reportInfo.resultList[index]
                                                    ?.testDate,
                                                'yyyy-MM-dd'
                                            )
                                        }}</span>
                                    </el-form-item>
                                </el-col>
                                <el-col :span="8">
                                    <el-form-item label="fa：">
                                        <span>{{
                                            reportInfo.resultList[index]?.fa
                                        }}</span>
                                    </el-form-item>
                                </el-col>
                                <el-col :span="8">
                                    <el-form-item label="fb：">
                                        <span>{{
                                            reportInfo.resultList[index]?.fb
                                        }}</span>
                                    </el-form-item>
                                </el-col>
                                <el-col :span="8">
                                    <el-form-item label="fc：">
                                        <span>{{
                                            reportInfo.resultList[index]?.fc
                                        }}</span>
                                    </el-form-item>
                                </el-col>
                                <el-col :span="8">
                                    <el-form-item label="da：">
                                        <span>{{
                                            reportInfo.resultList[index]?.da
                                        }}</span>
                                    </el-form-item>
                                </el-col>
                                <el-col :span="8">
                                    <el-form-item label="db：">
                                        <span>{{
                                            reportInfo.resultList[index]?.db
                                        }}</span>
                                    </el-form-item>
                                </el-col>
                                <el-col :span="8">
                                    <el-form-item label="dc：">
                                        <span>{{
                                            reportInfo.resultList[index]?.dc
                                        }}</span>
                                    </el-form-item>
                                </el-col>
                                <el-col :span="8">
                                    <el-form-item label="dUa：">
                                        <span>{{
                                            reportInfo.resultList[index]?.dUa
                                        }}</span>
                                    </el-form-item>
                                </el-col>
                                <el-col :span="8">
                                    <el-form-item label="dUb：">
                                        <span>{{
                                            reportInfo.resultList[index]?.dUb
                                        }}</span>
                                    </el-form-item>
                                </el-col>
                                <el-col :span="8">
                                    <el-form-item label="dUc：">
                                        <span>{{
                                            reportInfo.resultList[index]?.dUc
                                        }}</span>
                                    </el-form-item>
                                </el-col>
                                <el-col :span="8">
                                    <el-form-item label="Upta：">
                                        <span>{{
                                            reportInfo.resultList[index]?.Upta
                                        }}</span>
                                    </el-form-item>
                                </el-col>
                                <el-col :span="8">
                                    <el-form-item label="Uptb：">
                                        <span>{{
                                            reportInfo.resultList[index]?.Uptb
                                        }}</span>
                                    </el-form-item>
                                </el-col>
                                <el-col :span="8">
                                    <el-form-item label="Uptc：">
                                        <span>{{
                                            reportInfo.resultList[index]?.Uptc
                                        }}</span>
                                    </el-form-item>
                                </el-col>
                                <el-col :span="8">
                                    <el-form-item label="Uyba：">
                                        <span>{{
                                            reportInfo.resultList[index]?.Uyba
                                        }}</span>
                                    </el-form-item>
                                </el-col>
                                <el-col :span="8">
                                    <el-form-item label="Uybb：">
                                        <span>{{
                                            reportInfo.resultList[index]?.Uybb
                                        }}</span>
                                    </el-form-item>
                                </el-col>
                                <el-col :span="8">
                                    <el-form-item label="Uybc：">
                                        <span>{{
                                            reportInfo.resultList[index]?.Uybc
                                        }}</span>
                                    </el-form-item>
                                </el-col>
                                <el-col :span="8">
                                    <el-form-item label="r%：">
                                        <span>{{
                                            reportInfo.resultList[index]?.rate
                                        }}</span>
                                    </el-form-item>
                                </el-col>
                                <el-col :span="8">
                                    <el-form-item label="res1：">
                                        <span>{{
                                            reportInfo.resultList[index]?.res1
                                        }}</span>
                                    </el-form-item>
                                </el-col>
                                <el-col :span="8">
                                    <el-form-item label="res2：">
                                        <span>{{
                                            reportInfo.resultList[index]?.res2
                                        }}</span>
                                    </el-form-item>
                                </el-col>
                                <el-col :span="8">
                                    <el-form-item label="res3：">
                                        <span>{{
                                            reportInfo.resultList[index]?.res3
                                        }}</span>
                                    </el-form-item>
                                </el-col>
                                <el-col :span="8">
                                    <el-form-item label="res4：">
                                        <span>{{
                                            reportInfo.resultList[index]?.res4
                                        }}</span>
                                    </el-form-item>
                                </el-col>
                            </el-row>
                        </div>
                    </div>
                </el-form>
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
    reportInfo: {
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

// 日期格式化计算属性
const formatDate = dateStr => {
    if (!dateStr) return '';
    return format(new Date(dateStr), 'yyyy-MM-dd');
};
</script>

<style lang="less" scoped>
@import url('../modal.less');

.modal {
    width: 1000px;
    height: 600px;
    overflow: auto;
}

h4 {
    margin-bottom: 10px;
    color: #666;
}
</style>
