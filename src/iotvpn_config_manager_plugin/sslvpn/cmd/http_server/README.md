# SSL VPN Config Agent HTTP服务

这个HTTP服务器用于验证SSL VPN Config Agent C函数库的功能，将C函数库封装为HTTP接口。

## 编译和运行

确保已经编译好了`libsslvpn.so`库，并放置在`release/lib`目录下。

```bash
cd src/cmd/http_server
go build -o vpn-http-server
./vpn-http-server
```

服务器将在8080端口启动。

## API接口

服务器提供以下API接口，所有接口均使用POST方法：

- `/ccm/v1/manage/sslvpn/check-status`: 检查服务状态
- `/ccm/v1/manage/sslvpn/gendefault-cfg`: 生成默认配置
- `/ccm/v1/manage/sslvpn/restart-service`: 重启服务
- `/ccm/v1/manage/sslvpn/set-cfg`: 设置VPN配置
- `/ccm/v1/manage/sslvpn/get-cfg`: 查询VPN配置
- `/ccm/v1/manage/sslvpn/set-user`: 设置用户
- `/ccm/v1/manage/sslvpn/get-user`: 查询用户
- `/ccm/v1/manage/sslvpn/set-resource`: 设置资源
- `/ccm/v1/manage/sslvpn/get-resource`: 查询资源
- `/ccm/v1/manage/sslvpn/set-authority`: 设置权限
- `/ccm/v1/manage/sslvpn/get-authority`: 查询权限

## 使用Postman测试

项目根目录下的`postman_collection.json`文件包含了所有API接口的Postman配置。

1. 在Postman中导入该文件：
   - 点击"Import"按钮
   - 选择文件`postman_collection.json`
   - 点击"Import"完成导入

2. 导入后，你将看到"SSL VPN Config Agent API"集合，其中包含所有API接口。

3. 确保HTTP服务器已经启动，然后可以直接点击发送请求进行测试。

## 注意事项

- 确保`libsslvpn.so`库文件位于正确的位置（`release/lib`目录）
- 如果遇到权限问题，可能需要使用sudo运行服务器
- 服务器默认监听在8080端口，如需更改，请修改`main.go`中的端口号 