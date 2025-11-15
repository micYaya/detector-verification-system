// .eslintrc.cjs
module.exports = {
    root: true,
    env: {
        browser: true,
        es2021: true,
        node: true,
    },
    parserOptions: {
        ecmaVersion: 'latest',
        sourceType: 'module',
    },
    extends: [
        'eslint:recommended',
        'plugin:vue/vue3-recommended',
        'prettier', // 启用 prettier 配置，禁用与 Prettier 冲突的规则
    ],
    plugins: ['vue'],
    rules: {
        // 自定义规则
        semi: ['error', 'always'], // 强制分号
        quotes: ['error', 'single'], // 单引号
        indent: ['error', 2], // 缩进
        'no-trailing-spaces': ['error'], // 不要行尾空格
        'no-unused-vars': 'off',
        'vue/no-mutating-props': 'off',
        'no-console': 'warn',
        'no-debugger': 'warn',
        'vue/multi-word-component-names': 'off',
    },
};
