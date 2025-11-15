<template>
    <div class="header">
        <p>互感器二次压降检测仪检定系统</p>
    </div>
    <div class="wrapper">
        <h1>▎账户注册</h1>
        <div class="register-form">
            <el-form @submit.prevent="registerUser">
                <el-form-item label="账户名称：">
                    <el-input v-model="username" placeholder="请输入账户名称" />
                </el-form-item>
                <el-form-item label="手机号码：">
                    <el-input v-model="phone" placeholder="请输入手机号码" />
                </el-form-item>
                <el-form-item label="验证码：">
                    <el-input
                        v-model="verifyCode"
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
                <el-form-item label="密码：">
                    <el-input
                        v-model="password"
                        type="password"
                        show-password
                        placeholder="请输入密码"
                    />
                </el-form-item>
                <el-button type="primary" class="backBtn" @click="backToLogin">
                    返回登录
                </el-button>
                <el-button
                    type="primary"
                    class="registerBtn"
                    @click="registerUser"
                >
                    确定注册
                </el-button>
            </el-form>
        </div>
    </div>
</template>

<script setup>
import { ref, computed } from 'vue';
import { useRouter } from 'vue-router';
import { reqSendCode, register } from '@/api/login.js';
import { ElMessage, ElMessageBox } from 'element-plus';

const router = useRouter();
const username = ref('');
const phone = ref('');
const verifyCode = ref('');
const password = ref('');
const computeTime = ref(60);
let intervalId;

// 验证手机号有效性
const isPhoneValid = computed(() => /^1\d{10}$/.test(phone.value));

// 异步获取短信验证码
const getCode = async () => {
    console.log('开始计时');
    // 如果当前没有计时
    if (computeTime.value === 60) {
        // 启动倒计时
        console.log('启动倒计时');
        computeTime.value = 60;
        intervalId = setInterval(() => {
            computeTime.value--;
            console.log('time: ', computeTime.value);
            if (computeTime.value <= 0) {
                // 停止计时
                clearInterval(intervalId);
                computeTime.value = 60;
            }
        }, 1000);

        console.log('开始问后端要验证码');
        // 发送ajax请求(向指定手机号发送验证码短信)
        const result = await reqSendCode(phone.value, 'r');
        console.log(result);
        if (result.code === 1) {
            // 显示提示
            showAlert(result.msg);
            // 停止计时
            if (computeTime.value) {
                computeTime.value = 60;
                clearInterval(intervalId);
                intervalId = null;
            }
        }
    }
};

const showAlert = msg => {
    ElMessage.error(msg);
};

// 注册用户，检查手机和验证码有效性
const registerUser = async () => {
    if (!isPhoneValid.value) {
        showAlert('手机号不正确');
        return;
    }
    if (!/^\d{4}$/.test(verifyCode.value)) {
        showAlert('验证码必须是4位数字');
        return;
    }
    // 发送ajax请求注册用户
    const result = await register(
        phone.value,
        verifyCode.value,
        password.value
    );
    console.log(result);
    // 停止计时
    if (computeTime.value) {
        computeTime.value = 60;
        clearInterval(intervalId);
        intervalId = null;
    }

    // 根据结果数据处理，注册成功则返回
    if (result.code === 0) {
        // 链式调用
        await ElMessageBox.alert('注册成功，将返回系统登录界面', '注册情况', {
            confirmButtonText: '确定',
            type: 'success',
        });
        // 跳转到登录页
        router.push('/login');
    } else {
        // 显示警告提示
        showAlert(result.msg);
    }
};

// 返回登录界面
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

    .register-form {
        display: flex;
        justify-content: center;
        align-items: center;

        .backBtn,
        .registerBtn {
            width: 48%;
        }
    }
}

@media screen and (width <= 600px) {
    .header,
    .wrapper {
        width: 97% !important;
    }
}
</style>
