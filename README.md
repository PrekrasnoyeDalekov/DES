# DES

DES密码算法的C语言实现。

## 项目简介

DES全称为Data Encryption Standard，即数据加密标准，是一种使用密钥加密的块算法，1977年被美国联邦政府的国家标准局确定为联邦资料处理标准（FIPS），并授权在非密级政府通信中使用，随后该算法在国际上广泛流传开来。

此项目实现了DES加密和解密算法，支持对十六进制数，消息和文件的加密与解密操作。

## 功能

- 使用PKCS7规则进行填充和去填充
- 支持详细的运行日志输出（Verbose模式）
- 支持对一个64位十六进制数（明文块的最小单元）加密和解密，以供算法学习和演示
- 支持对一段文本消息加密解密
- 支持文件输入输出重定向
- 后续对大文件的加密解密将使用多线程

## 使用方法

1. 克隆仓库

```shell
git clone https://github.com/PrekrasnoyeDalekov/DES.git
cd DES
```

1. 编译项目

```shell
mingw32-make -f makefile.win all
```

此项目目前在Windows环境下使用MinGW编译器开发。

1. 运行程序

### 基本用法

```shell
./DES [-e | -d] -k <key> [-x <hex> | -m <message> | -f <file>] [-o <output>] [-h] [-v]
```

### 参数说明

- `-e`: 加密模式
- `-d`: 解密模式
- `-k <key>`: 指定64位十六进制数作为密钥
- `-x <hex>`: 指定一个64位的十六进制数进行加密或解密
- `-m <message>`: 指定消息文本进行加密或解密
- `-f <file>`: 指定文件进行加密或解密
- `-o <output>`: 指定输出文件（缺省则为标准输出流）
- `-h`: 显示帮助信息
- `-v`: 启用详细模式，输出运行日志

### 示例

1. 加密十六进制数，并输出运行日志：

```shell
./DES -e -k 0x12345678 -x 0x789abc -v
```

1. 加密消息

```shell
./DES -e -k 0x12345678 -m "Hello, World!"
```

1. 加密文件，并将加密结果输出到指定文件

```shell
./DES -e -k 0x12345678 -f input.txt -o encrypted.txt
```

1. 解密文件，并将解密结果输出到指定文件

```shell
./DES -d -k 0x12345678 -f encrypted.txt -o decrypted.txt
```

1. 对同一文件进行加密再解密，其校验和与源文件相同

```shell
PS > .\DES.exe -e -k 0x999 -f DES.exe -o encrypted
PS > .\DES.exe -d -k 0x999 -f encrypted -o decrypted
PS > md5sum .\DES.exe
\1eaf569b2a42ef8ffbfa1487c9f9ef2c *.\\DES.exe
PS > md5sum .\decrypted
\1eaf569b2a42ef8ffbfa1487c9f9ef2c *.\\decrypted
```

## 文件结构

```plaintext
DES/
├── cipherkey.c        # 密钥生成相关代码
├── cipherkey.h        # 密钥生成相关头文件
├── decrypt.c          # 解密相关代码
├── decrypt.h          # 解密相关头文件
├── des.c              # DES 加密解密主逻辑
├── des.h              # DES 公共头文件
├── encrypt.c          # 加密相关代码
├── encrypt.h          # 加密相关头文件
├── main.c             # 程序入口
├── LICENSE            # 项目许可证（GPLv3）
├── README.md          # 项目说明文档
└── makefile.win       # Windows 平台的 Makefile
```
