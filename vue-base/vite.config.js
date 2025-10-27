import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import AutoImport from 'unplugin-auto-import/vite';
import Components from 'unplugin-vue-components/vite';
import { ElementPlusResolver } from 'unplugin-vue-components/resolvers';
import viteCompression from 'vite-plugin-compression';
import { visualizer } from 'rollup-plugin-visualizer';
import path from 'path';
// import cdnImport from 'vite-plugin-cdn-import';

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  const isProduction = mode === 'production';

  return {
    base: isProduction ? '/private-projects/' : '/', // 根据环境设置基础路径
    cacheDir: './node_modules/.vite', // 指定缓存目录
    plugins: [
      vue(),
      // // 配置 CDN 插件
      // cdnImport({
      //   // 仅在生产环境下启用
      //   prodUrl: isProduction
      //     ? 'https://cdn.jsdelivr.net/npm/{name}@{version}/{path}'
      //     : '',
      //   modules: [
      //     {
      //       name: 'vue',
      //       var: 'Vue', // Vue 的全局变量名
      //       path: 'dist/vue.global.prod.js', // Vue 的生产环境路径
      //     },
      //     {
      //       name: 'element-plus',
      //       var: 'ElementPlus', // Element Plus 的全局变量名
      //       path: 'dist/index.full.min.js', // Element Plus 的生产环境路径
      //       css: 'dist/index.css',
      //     },
      //     {
      //       name: 'vue-router',
      //       var: 'VueRouter', // vue-router 的全局变量名
      //       path: 'dist/vue-router.global.prod.js',
      //     },
      //     {
      //       name: 'vue-demi',
      //       var: 'VueDemi',
      //       path: 'https://cdn.jsdelivr.net/npm/vue-demi@0.14.6/lib/index.iife.min.js',
      //     },
      //     {
      //       name: 'pinia',
      //       var: 'Pinia', // Pinia 的全局变量名
      //       path: 'dist/pinia.iife.prod.js',
      //     },
      //   ],
      // }),
      viteCompression({
        algorithm: 'brotliCompress', // 开启 Brotli 压缩
        threshold: 10240, // 超过 10kB 的文件进行压缩
      }),
      visualizer({
        open: false, // 打包完成后自动打开浏览器查看报告
        filename: 'dist/stats.html', // 报告文件保存路径
        title: 'Vite Bundle Analysis',
        gzipSize: true, // 显示 Gzip 压缩后的文件大小
        brotliSize: true, // 显示 Brotli 压缩后的文件大小
        template: 'treemap', // 可视化模板
      }),
      AutoImport({
        resolvers: [ElementPlusResolver()],
      }),
      Components({
        resolvers: [ElementPlusResolver()],
      }),
    ],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, './src'),
      },
    },
    server: {
      historyApiFallback: true, // 开发环境启用 history 路由支持
    },
    build: {
      minify: isProduction ? 'esbuild' : false, // 生产环境使用esbuild压缩
      esbuild: isProduction ? {
        drop: ['console', 'debugger']
      } : undefined,
      rollupOptions: {
        // external: isProduction ? ['vue', 'element-plus', 'vue-router', 'pinia'] : [], // 排除 Vue 和 Element Plus
        output: {
          // globals: {
          //   vue: 'Vue',
          //   'element-plus': 'ElementPlus',
          //   'vue-router': 'VueRouter',
          //   pinia: 'Pinia',
          // },
          manualChunks(id) {
            if (id.includes('node_modules')) {
              // 拆分 Vue 核心库（vue、vue-router、pinia）
              if (id.includes('vue') || id.includes('vue-router') || id.includes('pinia')) {
                return 'vue-core';
              }
              // 拆分 Element Plus
              if (id.includes('element-plus')) {
                return 'element-plus';
              }
              if (id.includes('axios') || id.includes('lodash')) {
                return 'utils-libs';
              }
              if (id.includes('echarts')) {
                return 'echarts';
              }
              // 其他依赖统一放入 vendor
              return 'vendor';
            }
          },
          chunkFileNames: 'assets/[name]-[hash].js',
          assetFileNames: 'assets/[name]-[hash].[ext]',
        },
        cssCodeSplit: true, // 启用CSS代码分割
      },
    },
  };
});