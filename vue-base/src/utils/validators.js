export const validateID = (rule, value, callback) => {
    // 检查是否为空
    if (value === null || value === undefined || value === '') {
        callback(new Error('ID不能为空'));
        return;
    }

    // 将值转换为数字
    const num = Number(value);

    // 检查是否为有效数字
    if (isNaN(num)) {
        callback(new Error('ID必须是有效的数字'));
        return;
    }

    // 检查是否为整数
    if (!Number.isInteger(num)) {
        callback(new Error('ID必须是整数'));
        return;
    }

    // 检查是否为正整数
    if (num <= 0) {
        callback(new Error('ID必须是正整数'));
        return;
    }

    // 所有验证通过
    callback();
};
