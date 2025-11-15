<template>
    <div class="header">
        <p>互感器二次压降检测仪检定系统</p>
    </div>
    <div class="wrapper">
        <h1>▎重置密码</h1>
        <div class="reset-form">
            <el-form
                ref="FormRef"
                :model="formData"
                :rules="dataRules"
                @submit.prevent="reset"
            >
                <el-form-item label="登录账号：" prop="username">
                    <el-input
                        v-model="formData.username"
                        placeholder="请输入账号"
                    />
                </el-form-item>
                <el-form-item label="手机号码：" prop="phone">
                    <el-input
                        v-model="formData.phone"
                        placeholder="请输入手机号码"
                    />
                </el-form-item>
                <el-form-item label="验证码：" prop="verifyCode">
                    <el-input
                        v-model="formData.verifyCode"
                        placeholder="请输入验证码"
                        style="flex: 1"
                    />
                    <el-button
                        :disabled="!isPhoneValid"
                        type="primary"
                        style="right: 0"
                        @click="getCode"
                    >
                        {{
                            computeTime < 60
                                ? `${computeTime}秒后重试`
                                : '获取验证码'
                        }}
                    </el-button>
                </el-form-item>
                <el-form-item label="新密码：" prop="password1">
                    <el-input
                        v-model="formData.password1"
                        type="password"
                        show-password
                        placeholder="请输入密码"
                    />
                </el-form-item>
                <el-form-item label="密码二次确认：" prop="password2">
                    <el-input
                        v-model="formData.password2"
                        type="password"
                        show-password
                        placeholder="请再次确认密码"
                    />
                </el-form-item>
                <el-button type="primary" class="backBtn" @click="backToLogin">
                    返回登录页面
                </el-button>
                <el-button type="primary" class="resetBtn" @click="reset">
                    确定重置密码
                </el-button>
            </el-form>
        </div>
    </div>
</template>

<script setup>
import { ref, computed, onBeforeUnmount } from 'vue';
import { useRouter } from 'vue-router';
import { reqSendCode, resetPassword } from '@/api/login.js';
import { ElMessage, ElMessageBox } from 'element-plus';

const router = useRouter();

// 表单引用
const FormRef = ref(null);
// 表单数据
const formData = ref({
    username: '',
    phone: '',
    verifyCode: '',
    password1: '',
    password2: '',
});
// 校验规则
// 关于两次密码一致性的校验
const validatePassword2 = (rule, value, callback) => {
    if (value !== formData.value.password1) {
        callback(new Error('两次输入的密码不一致'));
    } else {
        callback();
    }
};
const dataRules = {
    username: [
        { required: true, message: '请输入用户名', trigger: 'blur' },
        {
            min: 4,
            max: 15,
            message: '用户名长度需在4到15个字符',
            trigger: 'blur',
        },
    ],
    phone: [
        { required: true, message: '请输入手机号', trigger: 'blur' },
        {
            pattern: /^1\d{10}$/,
            message: '手机号格式不正确',
            trigger: 'blur',
        },
    ],
    verifyCode: [
        { required: true, message: '请输入验证码', trigger: 'blur' },
        {
            pattern: /^\d{4}$/,
            message: '验证码需为4位数字',
            trigger: 'blur',
        },
    ],
    password1: [
        { required: true, message: '请输入密码', trigger: 'blur' },
        {
            pattern: /^[A-Za-z\d]{6,10}$/,
            message: '密码需6-10位字母或数字',
            trigger: 'blur',
        },
    ],
    password2: [
        { required: true, message: '请再次确定密码', trigger: 'blur' },
        { validator: validatePassword2, trigger: 'blur' },
    ],
};

const computeTime = ref(60);

let intervalId = null;
// 验证手机号有效性
const isPhoneValid = computed(() => /^1\d{10}$/.test(formData.value.phone));

// 倒计时逻辑
const startCountdown = () => {
    computeTime.value = 60;
    intervalId = setInterval(() => {
        computeTime.value--;
        if (computeTime.value <= 0) {
            resetCountdown();
        }
    }, 1000);
};

const resetCountdown = () => {
    clearInterval(intervalId);
    computeTime.value = 0;
    intervalId = null;
};

// 组件卸载时清理定时器
onBeforeUnmount(() => {
    if (intervalId) resetCountdown();
});

// 异步获取短信验证码
const getCode = async () => {
    try {
        await FormRef.value.validateField('phone');
        startCountdown();
        const result = await reqSendCode(formData.value.phone);
        if (result.code !== 0) {
            ElMessage.warning(result.msg);
            resetCountdown();
        }
    } catch (error) {
        // 验证失败自动显示错误信息
        console.log('获取密码失败：', error);
    }
};

// 重置密码，检查验证码有效性和密码二次输入一致性
const reset = async () => {
    try {
        const valid = await FormRef.value.validate();
        if (!valid) return;

        const { phone, verifyCode, password1 } = formData.value;
        const res = await resetPassword(phone, verifyCode, password1);

        if (res.code === 0) {
            await ElMessageBox.alert('密码重置成功，将返回登录页面', '成功', {
                type: 'success',
                confirmButtonText: '确定',
            });
            router.push('/login');
        } else {
            ElMessage.warning(res.msg);
        }
    } catch (error) {
        console.error('密码重置失败:', error);
        ElMessage.error('操作失败，请检查输入信息');
    }
};

const backToLogin = () => {
    router.push('/login');
};
</script>

<style lang="less">
.header {
    width: 100vw;
    height: 8vh;
    line-height: 8vh;
    color: #fff;
    background: #1e78bf;
    padding: 0 40px;

    p {
        font-size: 30px;
        margin: 0;
    }
}

.wrapper {
    width: 600px;
    margin: 150px auto;
    padding: 20px;
    border-radius: 5px;
    box-shadow: 0 2px 8px rgb(0 0 0 / 10%);

    .reset-form {
        display: flex;
        justify-content: center;
        align-items: center;

        .backBtn,
        .resetBtn {
            width: 48%;
        }
    }
}

@media screen and (width <= 600px) {
    .wrapper {
        width: 97% !important;
    }
}
</style>
