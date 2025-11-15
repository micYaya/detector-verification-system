import { createApp } from 'vue';
import App from './App.vue';
import router from './router';
// pinia的状态管理
import { createPinia } from 'pinia';
import ElementPlus from 'element-plus';
import zhCn from 'element-plus/es/locale/lang/zh-cn';
import 'element-plus/dist/index.css';
import { useLoginStore } from './store/index';
import * as ElementPlusIconsVue from '@element-plus/icons-vue';

// app:vue的实例对象，一个项目中有且只有一个
const app = createApp(App);
for (const [key, component] of Object.entries(ElementPlusIconsVue)) {
    app.component(key, component);
}
const pinia = createPinia();
app.use(pinia);
app.use(router);

const loginStore = useLoginStore();
loginStore.initUserInfo();

app.use(ElementPlus, {
    locale: zhCn,
});
app.mount('#app');
