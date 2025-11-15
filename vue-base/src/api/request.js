import api from './api';

// 获取设备列表
export const getDeviceList = async () => {
    try {
        const response = await api.get('/api/devices');
        return response.data;
    } catch (error) {
        console.error('获取设备列表失败', error);
        throw error;
    }
};

// 添加设备
export const add_device = async deviceInfo => {
    try {
        const response = await api.post('/api/devices', deviceInfo);
        return response.data;
    } catch (error) {
        console.error('保存设备信息失败', error);
        throw error;
    }
};

// 编辑设备
export const edit_device = async deviceInfo => {
    try {
        const response = await api.put(
            `/api/devices/${deviceInfo.id}`,
            deviceInfo
        );
        return response.data;
    } catch (error) {
        console.error('编辑设备信息失败', error);
        throw error;
    }
};

// 删除设备
export const delete_device = async id => {
    try {
        const response = await api.delete(`/api/devices/${id}`);
        return response.data;
    } catch (error) {
        console.error('删除设备信息失败', error);
        throw error;
    }
};

// 更新设备检测状态，任务状态变成“已完成”时，就算检测完成
export const updateDeviceStatus = async (deviceId, status) => {
    try {
        const response = await api.put(`/api/devices/${deviceId}/status`, {
            deviceStatus: status,
        });
        return response.data;
    } catch (error) {
        console.error('更新设备状态失败', error);
        throw error;
    }
};

// 获取结果列表
export const getResults = async () => {
    try {
        const response = await api.get('/api/results');
        return response.data;
    } catch (error) {
        console.error('获取结果列表失败', error);
        throw error;
    }
};

// 添加结果
export const add_result = async resultInfo => {
    try {
        await api.post('/api/results', resultInfo);
    } catch (error) {
        console.error('保存结果失败:', error);
        throw error;
    }
};

// 编辑结果
export const edit_result = async (resultId, resultInfo) => {
    try {
        await api.put(`/api/results/${resultId}`, resultInfo);
    } catch (error) {
        console.error('保存结果失败:', error);
        throw error;
    }
};

// 删除结果
export const delete_result = async resultId => {
    try {
        await api.delete(`/api/results/${resultId}`);
    } catch (error) {
        console.error('删除结果信息失败', error);
        throw error;
    }
};

// 获取检测项目列表
export const getInspectionItems = async () => {
    try {
        const response = await api.get('/api/inspection_items');
        return response.data;
    } catch (error) {
        console.error('获取检测项目列表失败', error);
        throw error;
    }
};

// 添加检测项目
export const add_inspectionItem = async itemInfo => {
    try {
        await api.post('/api/inspection_items', itemInfo);
    } catch (error) {
        console.error('保存检测项目信息失败', error);
        throw error;
    }
};

// 编辑检测项目
export const edit_inspectionItem = async (itemId, itemInfo) => {
    try {
        await api.put(`/api/inspection_items/${itemId}`, itemInfo);
    } catch (error) {
        console.error('编辑检测项目信息失败', error);
        throw error;
    }
};

// 删除检测项目
export const delete_inspectionItem = async itemId => {
    try {
        await api.delete(`/api/inspection_items/${itemId}`);
    } catch (error) {
        console.error('删除检测项目信息失败', error);
        throw error;
    }
};

// 获取设备任务
export const getTaskList = async id => {
    try {
        const response = await api.get(`/api/tasks?deviceId=${id}`);
        return response.data;
    } catch (error) {
        console.error('获取任务列表失败', error);
        throw error;
    }
};
// 获取任务列表
export const getTasks = async () => {
    try {
        const response = await api.get('/api/tasks');
        return response.data;
    } catch (error) {
        console.error('获取任务列表失败', error);
        throw error;
    }
};

// 获取任务列表（包含实验项目数量）
export const getTaskListWithItemCount = async () => {
    try {
        const response = await api.get('/api/tasks/with-item-count');
        return response.data;
    } catch (error) {
        console.error('获取任务列表失败（包含实验项目数量）', error);
        throw error;
    }
};

// 检查设备是否存在
export const checkDeviceExists = async deviceId => {
    try {
        const response = await api.get(`/api/devices/${deviceId}`);
        return response.data;
    } catch (error) {
        console.error('检查设备是否存在失败', error);
        throw error;
    }
};

// 创建任务
export const add_task = async taskInfo => {
    try {
        const response = await api.post('/api/tasks', taskInfo);
        return response.data;
    } catch (error) {
        console.error('创建任务失败', error);
        throw error;
    }
};

// 更新任务状态
export const updateTaskStatus = async (taskId, taskInfo) => {
    try {
        const response = await api.put(`/api/tasks/${taskId}`, taskInfo);
        return response.data;
    } catch (error) {
        console.error('更新任务状态失败', error);
        throw error;
    }
};

// 删除任务
export const delete_task = async taskId => {
    try {
        const response = await api.delete(`/api/tasks/${taskId}`);
        return response.data;
    } catch (error) {
        console.error('删除任务失败', error);
        throw error;
    }
};

// 执行 OCR 实验
export const performOcr = async deviceId => {
    try {
        const response = await api.post('/api/perform-ocr', {
            deviceId: deviceId,
        });
        return response.data;
    } catch (error) {
        console.error('执行 OCR 实验失败', error);
        throw error;
    }
};

// 获取报表
export const getReport = async deviceId => {
    try {
        const response = await api.get(`/api/reports/${deviceId}`);
        return response.data;
    } catch (error) {
        console.error('获取报表失败', error);
        throw error;
    }
};

// 获取近一个月送检设备数量
export const getDevicesMonth = async oneMonthAgo => {
    try {
        const response = await api.get(
            `/api/devices?inspectionDate_gte=${oneMonthAgo}`
        );
        return response.data;
    } catch (error) {
        console.error('获取近一个月送检设备数量失败', error);
        throw error;
    }
};

// 获取用户列表
export const getUsers = async () => {
    try {
        const response = await api.get('/api/users');
        return response.data;
    } catch (error) {
        console.error('获取用户列表失败', error);
        throw error;
    }
};

// 添加用户
export const add_user = async userInfo => {
    try {
        const response = await api.post('/api/users', userInfo);
        return response.data;
    } catch (error) {
        console.error('添加用户失败', error);
        throw error;
    }
};

// 编辑用户
export const edit_user = async (userId, userInfo) => {
    try {
        const response = await api.put(`/api/users/${userId}`, userInfo);
        return response.data;
    } catch (error) {
        console.error('编辑用户失败', error);
        throw error;
    }
};

// 删除用户
export const delete_user = async userId => {
    try {
        const response = await api.delete(`/api/users/${userId}`);
        return response.data;
    } catch (error) {
        console.error('删除用户失败', error);
        throw error;
    }
};
