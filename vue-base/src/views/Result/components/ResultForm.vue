<template>
    <el-form
        ref="resultForm"
        :model="resultInfo"
        label-width="150px"
        :show-message="false"
    >
        <el-row :gutter="20">
            <el-col :span="8">
                <el-form-item label="关联设备编号：">
                    <el-input
                        v-model="resultInfo.deviceId"
                        placeholder="输入设备ID"
                    />
                </el-form-item>
            </el-col>
            <el-col :span="8">
                <el-form-item label="二次电压（U）：">
                    <el-input
                        v-model.number="resultInfo.twoP"
                        placeholder="输入数值"
                    />
                </el-form-item>
            </el-col>
            <el-col :span="8">
                <el-form-item label="tanψ：">
                    <el-input
                        v-model.number="resultInfo.tanValue"
                        placeholder="输入数值"
                    />
                </el-form-item>
            </el-col>
        </el-row>

        <el-row :gutter="20">
            <el-col :span="8">
                <el-form-item label="计量点编号：">
                    <el-input
                        v-model.number="resultInfo.measuredId"
                        placeholder="输入编号"
                    />
                </el-form-item>
            </el-col>
            <el-col :span="8">
                <el-form-item label="温度：">
                    <el-input
                        v-model.number="resultInfo.temperature"
                        placeholder="输入数值"
                    />
                </el-form-item>
            </el-col>
            <el-col :span="8">
                <el-form-item label="湿度：">
                    <el-input
                        v-model.number="resultInfo.humidity"
                        placeholder="输入数值"
                    />
                </el-form-item>
            </el-col>
        </el-row>

        <el-row :gutter="20">
            <el-col :span="8">
                <el-form-item label="测试日期：">
                    <el-date-picker
                        v-model="resultInfo.testDate"
                        type="date"
                        placeholder="选择日期"
                    />
                </el-form-item>
            </el-col>
            <el-col :span="8">
                <el-form-item label="fa：">
                    <el-input
                        v-model.number="resultInfo.fa"
                        placeholder="输入数值"
                    />
                </el-form-item>
            </el-col>
            <el-col :span="8">
                <el-form-item label="fb：">
                    <el-input
                        v-model.number="resultInfo.fb"
                        placeholder="输入数值"
                    />
                </el-form-item>
            </el-col>
        </el-row>

        <el-row :gutter="20">
            <el-col :span="8">
                <el-form-item label="fc：">
                    <el-input
                        v-model.number="resultInfo.fc"
                        placeholder="输入数值"
                    />
                </el-form-item>
            </el-col>
            <el-col :span="8">
                <el-form-item label="da：">
                    <el-input
                        v-model.number="resultInfo.da"
                        placeholder="输入数值"
                    />
                </el-form-item>
            </el-col>
            <el-col :span="8">
                <el-form-item label="db：">
                    <el-input
                        v-model.number="resultInfo.db"
                        placeholder="输入数值"
                    />
                </el-form-item>
            </el-col>
        </el-row>

        <el-row :gutter="20">
            <el-col :span="8">
                <el-form-item label="dc：">
                    <el-input
                        v-model.number="resultInfo.dc"
                        placeholder="输入数值"
                    />
                </el-form-item>
            </el-col>
            <el-col :span="8">
                <el-form-item label="dUa：">
                    <el-input
                        v-model.number="resultInfo.dUa"
                        placeholder="输入数值"
                    />
                </el-form-item>
            </el-col>
            <el-col :span="8">
                <el-form-item label="dUb：">
                    <el-input
                        v-model.number="resultInfo.dUb"
                        placeholder="输入数值"
                    />
                </el-form-item>
            </el-col>
        </el-row>

        <el-row :gutter="20">
            <el-col :span="8">
                <el-form-item label="dUc：">
                    <el-input
                        v-model.number="resultInfo.dUc"
                        placeholder="输入数值"
                    />
                </el-form-item>
            </el-col>
            <el-col :span="8">
                <el-form-item label="Upta：">
                    <el-input
                        v-model.number="resultInfo.Upta"
                        placeholder="输入数值"
                    />
                </el-form-item>
            </el-col>
            <el-col :span="8">
                <el-form-item label="Uptb：">
                    <el-input
                        v-model.number="resultInfo.Uptb"
                        placeholder="输入数值"
                    />
                </el-form-item>
            </el-col>
        </el-row>

        <el-row :gutter="20">
            <el-col :span="8">
                <el-form-item label="Uptc：">
                    <el-input
                        v-model.number="resultInfo.Uptc"
                        placeholder="输入数值"
                    />
                </el-form-item>
            </el-col>
            <el-col :span="8">
                <el-form-item label="Uyba：">
                    <el-input
                        v-model.number="resultInfo.Uyba"
                        placeholder="输入数值"
                    />
                </el-form-item>
            </el-col>
            <el-col :span="8">
                <el-form-item label="Uybb：">
                    <el-input
                        v-model.number="resultInfo.Uybb"
                        placeholder="输入数值"
                    />
                </el-form-item>
            </el-col>
        </el-row>

        <el-row :gutter="20">
            <el-col :span="8">
                <el-form-item label="Uybc：">
                    <el-input
                        v-model.number="resultInfo.Uybc"
                        placeholder="输入数值"
                    />
                </el-form-item>
            </el-col>
            <el-col :span="8">
                <el-form-item label="r%：">
                    <el-input
                        v-model.number="resultInfo.rate"
                        placeholder="输入数值"
                    />
                </el-form-item>
            </el-col>
            <el-col :span="8">
                <el-form-item label="res1：">
                    <el-input
                        v-model.number="resultInfo.res1"
                        placeholder="输入数值"
                    />
                </el-form-item>
            </el-col>
        </el-row>

        <el-row :gutter="20">
            <el-col :span="8">
                <el-form-item label="res2：">
                    <el-input
                        v-model.number="resultInfo.res2"
                        placeholder="输入数值"
                    />
                </el-form-item>
            </el-col>
            <el-col :span="8">
                <el-form-item label="res3：">
                    <el-input
                        v-model.number="resultInfo.res3"
                        placeholder="输入数值"
                    />
                </el-form-item>
            </el-col>
            <el-col :span="8">
                <el-form-item label="res4：">
                    <el-input
                        v-model.number="resultInfo.res4"
                        placeholder="输入数值"
                    />
                </el-form-item>
            </el-col>
        </el-row>
    </el-form>
</template>

<script setup>
import { defineProps } from 'vue';

const props = defineProps({
    resultInfo: {
        type: Object,
        default: () => ({}),
    },
});
</script>

<style scoped></style>
