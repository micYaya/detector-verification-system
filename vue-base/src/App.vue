<template>
    <div id="app">
        <!-- 路由出口 -->
        <router-view />
    </div>
</template>

<script setup></script>

<style lang="less">
html,
body {
    height: 100%;
    margin: 0;
    padding: 0;
    font-size: 16px;
}

#app {
    height: 100%;
    min-height: 100vh;
}
</style>
