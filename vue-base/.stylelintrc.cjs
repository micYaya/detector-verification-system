// .stylelintrc.cjs
module.exports = {
    extends: [
        'stylelint-config-standard',
        'stylelint-config-html/vue', // 支持 .vue 文件中的 <style>
        'stylelint-config-prettier', // 禁用与 Prettier 冲突的规则
    ],
    overrides: [
        {
            files: ['**/*.less'],
            customSyntax: 'postcss-less',
        },
    ],
    rules: {
        'no-empty-source': null,
        'selector-class-pattern': null, // 关闭类名规则
    },
};
