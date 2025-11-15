/**
 * 自签名SSL证书生成脚本
 * 用于开发环境或测试HTTPS功能
 * 生产环境应使用正规CA机构颁发的证书
 */
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// 确保ssl目录存在
const sslDir = path.join(__dirname);
if (!fs.existsSync(sslDir)) {
    fs.mkdirSync(sslDir, { recursive: true });
}

// 生成自签名证书的命令
const generateCertCmd = `
  openssl req -x509 -newkey rsa:2048 -keyout ${path.join(sslDir, 'private.key')} -out ${path.join(sslDir, 'certificate.crt')} -days 365 -nodes -subj "/CN=localhost"
`;

try {
    console.log('正在生成自签名SSL证书...');
    execSync(generateCertCmd, { stdio: 'inherit' });
    console.log('SSL证书生成成功！');
    console.log(`私钥路径: ${path.join(sslDir, 'private.key')}`);
    console.log(`证书路径: ${path.join(sslDir, 'certificate.crt')}`);
    console.log(
        '\n注意: 这是自签名证书，仅用于开发环境。生产环境请使用正规CA机构颁发的证书。'
    );
} catch (error) {
    console.error('生成SSL证书失败:', error.message);
    console.log('\n请确保已安装OpenSSL，或手动生成SSL证书。');
}
