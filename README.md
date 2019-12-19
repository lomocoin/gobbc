# BBC 签名库 in go

修改自: https://github.com/bigbangcore/OffLineSignLib

多签部分参考core代码实现

## TODO
- 增加更多的测试用例
- 增加持续集成测试
- 代码审计

## To 开发人员
Bigbang 的release notes不够详细，不能依靠release notes判断改动，在升级新包的时候务必执行完整的集成测试

- 当前目录下 `go test `
- qa 目录下 `go test`

增加新的特性也务必确保测试用例的覆盖率，至少需要确保核心功能可以正常使用

测试：`make test`
集成测试：`make qaTest`
all: `make all`

## Features

- 生成密钥对、地址
- 交易序列化和解析
- 使用私钥签名
- 多签地址交易签名

## Missing features

- 部分模版地址签名支持


## 其他

开发过程中的一些小插曲参考 `doc` 目录
