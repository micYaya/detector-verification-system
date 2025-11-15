<template>
    <div class="login-container">
        <div class="login-box">
            <div class="wrapper">
                <h1>互感器二次压降检测仪检定系统</h1>

                <el-tabs
                    v-model="currentLoginType"
                    type="card"
                    style="position: relative; width: 100%"
                >
                    <!-- 密码登录 -->
                    <el-tab-pane label="密码登录" name="password">
                        <el-form
                            ref="passwordFormRef"
                            :model="passwordForm"
                            :rules="passwordRules"
                            @submit.prevent="handlePasswordLogin"
                        >
                            <el-form-item label="用户名:" prop="username">
                                <el-input
                                    v-model="passwordForm.username"
                                    placeholder="请输入用户名"
                                />
                            </el-form-item>
                            <el-form-item label="密码:" prop="password">
                                <el-input
                                    v-model="passwordForm.password"
                                    type="password"
                                    show-password
                                    placeholder="请输入密码"
                                />
                            </el-form-item>
                            <el-checkbox
                                v-model="rememberMe"
                                label="七天免登录"
                                size="large"
                            />
                            <br />
                            <a
                                href="/register"
                                style="text-decoration: none; color: #19e"
                                >注册账号</a
                            >
                            <a
                                href="/forget-password"
                                style="
                                    text-decoration: none;
                                    color: #19e;
                                    position: absolute;
                                    right: 0;
                                "
                                >忘记密码</a
                            >
                            <br /><br />
                            <el-button
                                type="primary"
                                class="loginBtn"
                                @click="handlePasswordLogin"
                            >
                                登录
                            </el-button>
                        </el-form>
                    </el-tab-pane>

                    <!-- 短信登录 -->
                    <el-tab-pane label="短信登录" name="verifyCode">
                        <el-form
                            ref="smsFormRef"
                            :model="smsForm"
                            :rules="smsRules"
                            @submit.prevent="handleVerifyCodeLogin"
                        >
                            <el-form-item label="手机号:" prop="phone">
                                <el-input
                                    v-model="smsForm.phone"
                                    placeholder="请输入手机号"
                                />
                            </el-form-item>
                            <el-form-item label="验证码:" prop="verifyCode">
                                <el-input
                                    v-model="smsForm.verifyCode"
                                    placeholder="请输入验证码"
                                    style="flex: 1"
                                />
                                <el-button
                                    :disabled="!isPhoneValid || isCounting"
                                    type="primary"
                                    style="width: 30%"
                                    @click="getCode"
                                >
                                    {{
                                        isCounting
                                            ? `${computeTime}秒后重试`
                                            : '获取验证码'
                                    }}
                                </el-button>
                            </el-form-item>
                            <p>
                                <b>如获取不到验证码</b><br />
                                1.请检查短信是否被安全软件拦截。<br />
                                2.网络原因，短信可能延迟到达。
                            </p>
                            <el-button
                                type="primary"
                                class="loginBtn"
                                @click="handleVerifyCodeLogin"
                            >
                                登录
                            </el-button>
                        </el-form>
                    </el-tab-pane>
                </el-tabs>
            </div>
        </div>
    </div>
</template>

<script setup>
import { ref, computed } from 'vue';
import { useRouter } from 'vue-router';
import { useLoginStore } from '@/store/index';
import { reqSendCode, reqSmsLogin, checkUser } from '@/api/login.js';
import { ElMessage } from 'element-plus';

const router = useRouter();
const loginStore = useLoginStore();
const currentLoginType = ref('password');
// 表单引用
const passwordFormRef = ref(null);
const smsFormRef = ref(null);

// 表单数据
const passwordForm = ref({
    username: '',
    password: '',
});

const smsForm = ref({
    phone: '',
    verifyCode: '',
});

// 校验规则
const passwordRules = {
    username: [
        { required: true, message: '请输入用户名', trigger: 'blur' },
        {
            min: 4,
            max: 15,
            message: '用户名长度需在4到15个字符',
            trigger: 'blur',
        },
    ],
    password: [
        { required: true, message: '请输入密码', trigger: 'blur' },
        {
            pattern: /^[A-Za-z\d]{6,10}$/,
            message: '密码需6-10位字母或数字',
            trigger: 'blur',
        },
    ],
};

const smsRules = {
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
};
// 七天免登录
const rememberMe = ref(false);
// 短信验证码相关
const computeTime = ref(0);
const isCounting = computed(() => computeTime.value > 0);
let intervalId = null;

const isPhoneValid = computed(() => /^1\d{10}$/.test(smsForm.value.phone));

// 获取验证码
const getCode = async () => {
    try {
        await smsFormRef.value.validateField('phone');
        startCountdown();
        const result = await reqSendCode(smsForm.value.phone);
        if (result.code !== 0) {
            ElMessage.warning(result.msg);
            resetCountdown();
        }
    } catch (error) {
        // 验证失败自动显示错误信息
        console.log('获取密码失败：', error);
    }
};

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

// 密码登录
const handlePasswordLogin = async () => {
    passwordFormRef.value.validate(async valid => {
        if (valid) {
            console.log(rememberMe.value);
            try {
                const result = await checkUser(
                    passwordForm.value.username,
                    passwordForm.value.password,
                    rememberMe.value // 七天免登录复选框
                );
                if (result.code === 0) {
                    // const userinfo = { user: passwordForm.value.username };
                    // loginStore.setUserInfo(userinfo);
                    // console.log('result: ', result.data)

                    const { nickname, role, accessToken } = result.data;
                    const userinfo = {
                        username: nickname,
                        role: role,
                    };
                    loginStore.setUserInfo(nickname, role);
                    // const { accessToken, rememberMe } = result.data;
                    console.log(accessToken, rememberMe.value);
                    if (rememberMe.value) {
                        localStorage.setItem('accessToken', accessToken);
                        localStorage.setItem('rememberMe', 'true');
                    } else {
                        sessionStorage.setItem('accessToken', accessToken);
                        localStorage.setItem('rememberMe', 'false'); // 保留 rememberMe 设置
                    }

                    localStorage.setItem('user', JSON.stringify(userinfo));
                    router.push('/home');
                } else {
                    ElMessage.warning(result.msg);
                }
            } catch (error) {
                ElMessage.error('登录请求失败');
                console.log(error);
            }
        }
    });
};

// 验证码登录
const handleVerifyCodeLogin = async () => {
    smsFormRef.value.validate(async valid => {
        if (valid) {
            try {
                const result = await reqSmsLogin(
                    smsForm.value.phone,
                    smsForm.value.verifyCode
                );
                if (result.code === 0) {
                    const user = result.data;
                    // const userinfo = { user: user.nickname };
                    loginStore.setUserInfo(user.nickname, user.role);
                    loginStore.setPhoneNumber(smsForm.value.phone);
                    const userinfo = {
                        username: user.nickname,
                        role: user.role,
                    };

                    // 存储两个令牌、用户信息和rememberMe
                    const { accessToken } = result.data;
                    // console.log('短信登录accessToken: ', accessToken);
                    // console.log('短信登录refreshToken: ', refreshToken);
                    // 手机号码短信登录没有七天免登录选项
                    localStorage.setItem('rememberMe', 'false');
                    sessionStorage.setItem('accessToken', accessToken);

                    localStorage.setItem('user', JSON.stringify(userinfo));
                    router.push('/home');
                    resetCountdown();
                } else {
                    ElMessage.warning(result.msg);
                }
            } catch (error) {
                ElMessage.error('登录请求失败');
            }
        }
    });
};
</script>

<style lang="less" scoped>
.login-container {
    width: 100%;
    height: 100%;
    background: #eee;
    background-image: url('@/assets/images/login_bg.svg');
    background-size: cover;
    display: flex;
    justify-content: center;
    align-items: center;

    .login-box {
        width: 96%;
        height: 94%;
        padding: 0 50px;
        background-color: rgb(255 255 255 / 75%);
        border-radius: 10px;
        display: flex;
        align-items: center;
        justify-content: center;

        .wrapper {
            width: 100%;
            max-width: 480px;
            padding: 20px;
            background-color: #f9f9f9;
            border-radius: 5px;
            box-shadow: 0 2px 10px 2px rgb(0 0 0 / 10%);

            .loginBtn {
                width: 100%;
            }
        }

        :deep(.el-tabs__nav) {
            width: 100%;
        }

        :deep(.el-tabs__item) {
            width: 50%;
        }
    }
}

@media screen and (width <= 600px) {
    .wrapper {
        width: 97% !important;
    }
}
</style>
