<template>
    <div class="pagination-wrapper">
        <el-pagination
            :current-page="currentPage"
            :page-sizes="pageSizes"
            :page-size="pageSize"
            layout="total, prev, pager, next, sizes, jumper"
            :total="total"
            @size-change="handleSizeChange"
            @current-change="handleCurrentChange"
        />
    </div>
</template>

<script setup>
import { defineProps, defineEmits } from 'vue';

// 接收父组件传递的参数
defineProps({
    currentPage: {
        type: Number,
        required: true,
    },
    pageSize: {
        type: Number,
        required: true,
    },
    total: {
        type: Number,
        required: true,
    },
    pageSizes: {
        type: Array,
        default: () => [5, 10, 15, 20],
    },
});

// 定义事件，用于向父组件传递分页变化
const emit = defineEmits(['update:currentPage', 'update:pageSize']);

// 分页大小改变时的回调
const handleSizeChange = newSize => {
    emit('update:pageSize', newSize); // 通知父组件更新 pageSize
};

// 当前页码改变时的回调
const handleCurrentChange = newPage => {
    emit('update:currentPage', newPage); // 通知父组件更新 currentPage
};
</script>

<style scoped>
.pagination-wrapper {
    margin-top: 20px;
    text-align: center;
}
</style>
