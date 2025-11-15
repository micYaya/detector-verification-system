<template>
    <div class="list-container">
        <el-breadcrumb separator="/" class="breadcrumb">
            <el-breadcrumb-item>首页</el-breadcrumb-item>
            <el-breadcrumb-item>用户管理</el-breadcrumb-item>
        </el-breadcrumb>
        <div class="upper-section">
            <el-form
                :inline="true"
                :model="query"
                style="display: flex; justify-items: center"
            >
                <div class="search-filter">
                    <div class="filter">
                        <el-form-item label="角色">
                            <el-input
                                v-model="query.nickname"
                                placeholder="输入角色"
                                clearable
                            />
                        </el-form-item>
                        <el-form-item label="超级管理员">
                            <el-select v-model="query.role" placeholder="全部">
                                <el-option label="全部" value="" />
                                <el-option label="是" value="admin" />
                                <el-option label="否" value="user" />
                            </el-select>
                        </el-form-item>
                    </div>
                    <el-button type="primary" @click="applyFilter"
                        >搜索</el-button
                    >
                </div>
            </el-form>
            <el-button
                type="primary"
                icon="Plus"
                @click="openDialog()"
                class="add-button"
                >新增角色</el-button
            >
        </div>
        <br />
        <div class="lower-section">
            <el-table
                :data="filteredData"
                :cell-style="{ textAlign: 'center' }"
                :header-cell-style="{ textAlign: 'center' }"
                border
            >
                <el-table-column prop="id" label="Id" width="200" />
                <el-table-column prop="nickname" label="角色" width="150" />
                <el-table-column
                    prop="role"
                    label="角色名称"
                    :formatter="formatRoleName"
                    width="250"
                />
                <el-table-column label="超级管理员" width="200">
                    <template #default="{ row }">
                        <el-tag
                            :type="row.role === 'admin' ? 'success' : 'danger'"
                        >
                            {{ row.role === 'admin' ? '是' : '否' }}
                        </el-tag>
                    </template>
                </el-table-column>
                <el-table-column
                    prop="createTime"
                    label="创建时间"
                    width="330"
                    :formatter="formatTime"
                />
                <el-table-column label="操作" fixed="right">
                    <template #default="{ row }">
                        <el-button type="primary" text @click="openDialog(row)"
                            >编辑</el-button
                        >
                        <el-button
                            type="danger"
                            text
                            @click="handleDelete(row.id)"
                            >删除</el-button
                        >
                    </template>
                </el-table-column>
            </el-table>

            <el-pagination
                background
                layout="total, sizes, prev, pager, next, jumper"
                :total="total"
                :page-size="pagination.pageSize"
                :current-page="pagination.currentPage"
                @current-change="handlePageChange"
                @size-change="handleSizeChange"
                class="pagination-wrapper"
            />
        </div>

        <!-- 弹窗 -->
        <el-dialog :title="dialogTitle" v-model="dialogVisible" width="400px">
            <el-form :model="form" label-width="100px">
                <el-form-item label="用户">
                    <el-input v-model="form.nickname" />
                </el-form-item>
                <el-form-item label="手机号码">
                    <el-input v-model="form.phone" />
                </el-form-item>
                <el-form-item label="角色类型">
                    <el-select v-model="form.role">
                        <el-option label="超级管理员" value="admin" />
                        <el-option label="普通用户" value="user" />
                    </el-select>
                </el-form-item>
            </el-form>
            <template #footer>
                <el-button @click="dialogVisible = false">取消</el-button>
                <el-button type="primary" @click="handleSave">确定</el-button>
            </template>
        </el-dialog>
    </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue';
import { ElMessageBox, ElMessage } from 'element-plus';
import { getUsers, add_user, edit_user, delete_user } from '@/api/request';
const query = ref({ nickname: '', role: '' });
const tableData = ref([]);
const filteredData = ref([]);
const pagination = ref({ currentPage: 1, pageSize: 10 });

const dialogVisible = ref(false);
const dialogTitle = ref('新增角色');
const form = ref({ id: '', nickname: '', phone: '', role: '', createTime: '' });
const total = ref(0);

const fetchData = async () => {
    try {
        const res = await getUsers();
        console.log(res);
        if (res.list) {
            tableData.value = res.list;
            filteredData.value = tableData.value;
            total.value = res.total;
        } else {
            tableData.value = [];
            filteredData.value = [];
            total.value = 0;
        }
    } catch (error) {
        console.error('获取用户数据失败:', error);
        tableData.value = [];
        filteredData.value = [];
        total.value = 0;
    }
};

const applyFilter = () => {
    const matched = tableData.value.filter(item => {
        const matchNickname =
            query.value.nickname === '' ||
            item.nickname.includes(query.value.nickname);
        const matchRole =
            query.value.role === '' || item.role === query.value.role;
        return matchNickname && matchRole;
    });

    total.value = matched.length;

    const start =
        (pagination.value.currentPage - 1) * pagination.value.pageSize;
    const end = start + pagination.value.pageSize;
    filteredData.value = matched.slice(start, end);
};

const formatRoleName = (_, __, row) => {
    return row === 'admin' ? '超级管理员' : '普通操作员';
};

const formatTime = (_, __, row) => {
    const date = new Date(row);
    const formatTime = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')} ${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}:${String(date.getSeconds()).padStart(2, '0')}`;
    return formatTime;
};

const handlePageChange = val => {
    pagination.value.currentPage = val;
    applyFilter(); // 翻页时更新数据
};

const handleSizeChange = val => {
    pagination.value.pageSize = val;
    pagination.value.currentPage = 1;
    applyFilter(); // 修改每页数量时也要重新分页
};

const openDialog = (row = null) => {
    if (row) {
        dialogTitle.value = '编辑角色';
        form.value = { ...row };
    } else {
        dialogTitle.value = '新增角色';
        form.value = { id: '', nickname: '', role: '', createTime: Date.now() };
    }
    dialogVisible.value = true;
};

const handleSave = async () => {
    if (form.value.id) {
        await edit_user(form.value.id, form.value);
        ElMessage.success('编辑成功');
    } else {
        form.value.id = Date.now().toString();
        await add_user(form.value);
        ElMessage.success('新增成功');
    }
    dialogVisible.value = false;
    fetchData();
};

const handleDelete = id => {
    ElMessageBox.confirm('确认删除该角色？', '警告', { type: 'warning' })
        .then(async () => {
            await delete_user(id);
            ElMessage.success('删除成功');
            fetchData();
        })
        .catch(() => {});
};

onMounted(fetchData);
</script>

<style scoped>
@import '@/views/list_share.less';
.add-button {
    margin-bottom: 20px;
}
:deep(.el-select) {
    --el-select-width: 120px;
}
.search-filter {
    margin-top: 0;
    .filter {
        margin-top: 18px;
    }
}
@media screen and (max-width: 700px) {
    .search-filter {
        flex-direction: column; /* 垂直排列 */
        align-items: flex-start;
        margin: 10px;
    }
}
</style>
