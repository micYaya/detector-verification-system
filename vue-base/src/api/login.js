import ajax from './ajax';
import { encrypt } from '@/utils/crypto';
const enableEncryption = import.meta.env.VITE_ENABLE_API_ENCRYPTION === 'true';

const reqSendCode = (phone, type = 'normal') =>
    ajax('/api/sendcode', { phone, type });

const reqSmsLogin = (phone, code) =>
    ajax('/api/login_sms', { phone, code }, 'POST');

const resetPassword = (phone, code, password) => {
    if (enableEncryption) {
        const data = encrypt({ phone, code, password });
        return ajax('api/reset_password', { encrypted: true, data }, 'POST');
    }
    return ajax('api/reset_password', { phone, code, password }, 'POST');
};

const register = (phone, code, password) => {
    if (enableEncryption) {
        const data = encrypt({ phone, code, password });
        return ajax('api/register', { encrypted: true, data }, 'POST');
    }
    return ajax('api/register', { phone, code, password }, 'POST');
};

const checkUser = (username, password = '', remember = false) => {
    if (enableEncryption) {
        const data = encrypt({ username, password, remember });
        return ajax('/api/check_user', { encrypted: true, data }, 'POST');
    }
    return ajax('/api/check_user', { username, password, remember }, 'POST');
};

export { reqSendCode, reqSmsLogin, resetPassword, register, checkUser };
