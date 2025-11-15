<template>
    <div class="home-container">
        <Menu class="menu" :is-collapsed="isCollapsed" />
        <Content class="content" />
    </div>
</template>

<script setup>
import Menu from './Menu.vue';
import Content from './Content.vue';
import { computed, ref, onMounted, onBeforeUnmount } from 'vue';

const isCollapsed = ref(false);
const menuWidth = computed(() => (isCollapsed.value ? '60px' : '15%'));
const handleResize = () => {
    isCollapsed.value = window.innerWidth < 1300;
};

onMounted(() => {
    window.addEventListener('resize', handleResize);
    handleResize();
});

onBeforeUnmount(() => {
    window.removeEventListener('resize', handleResize);
});
</script>

<style lang="less" scoped>
.home-container {
    display: flex;
    flex-direction: row;
    width: 100%;
    height: 100%;
    background-color: #f5f5f5;
}

.menu {
    top: 0;
    height: auto;
    overflow: auto;
    transition: width 0.3s ease;
    width: v-bind('menuWidth');
}

.content {
    top: 0;
    flex: 1;
    transition: all 0.3s ease;
}

@media screen and (width <= 600px) {
    .menu {
        width: 18% !important;
        height: 100% !important;
    }
}
</style>
