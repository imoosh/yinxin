12.1.	检查服务状态
	请求示例
POST /ccm/v1/manage/sslvpn/check-status HTTP/1.1 
Content-Length：ContentLength 
Content-Type:application/json;charset=UTF-8 
{
    
}
	响应示例
{
    "code": 0, //错误码
    "message": "code decribe msg", //错误描述
    "result":{
        "cfg_is_default":true,//是否是默认配置文件
        "cfg_status":true,//配置文件是否正确
        "service_staus":true//服务是否已启动
    }
}



12.2.	生成默认配置、恢复默认配置
	请求示例
POST /ccm/v1/manage/sslvpn/gendefault-cfg HTTP/1.1 
Content-Length：ContentLength 
Content-Type:application/json;charset=UTF-8 
{
    
}
	响应示例
{
    "code":0,//错误码
    "message":"code decribe msg",//错误描述
    "result":{} 
}



12.3.	重启服务
	请求示例
POST /ccm/v1/manage/sslvpn/restart-service HTTP/1.1 
Content-Length：ContentLength 
Content-Type:application/json;charset=UTF-8 
{
    
}
	响应示例
{
    "code":0,//错误码
    "message":"code decribe msg",//错误描述
    "result":{} 
}


12.4.	VPN参数设置
	请求示例
POST /ccm/v1/manage/sslvpn/set-cfg HTTP/1.1 
Content-Length：ContentLength 
Content-Type:application/json;charset=UTF-8 
{
    "port": 111, //监听端口 前端传入
    "max-clients": 1000, //最大允许的用户数 前端传入
    "verb": 3, //日志级别 0~11
    "data-ciphers": [ //加密算法套件
        "AES-256-GCM",
        "AES-128-GCM",
    ],
    "push_dns": "8.8.8.8", //推送DNS服务器地址给客户端
    "push_route_defalut": false, //是否让客户端将所有流量都通过VPN，如果为是则push_route将被忽略    
    "push_route": //客户端指定子网流量通过vpn
    [
        {
            "net": "192.168.1.0",
            "mask": "255.255.255.0"
        }
    ]
}


	响应示例
{
"code":0,//错误码
"message":"code decribe msg",//错误描述
"result":{} /
}

12.5.	VPN参数查询
	请求示例
POST /ccm/v1/manage/sslvpn/get-cfg HTTP/1.1 
Content-Length：ContentLength 
Content-Type:application/json;charset=UTF-8 
{
    
}
	响应示例
{
    "code": 0, //错误码
    "message": "code decribe msg", //错误描述
    "result":{
        "port": 111, //监听端口 前端传入
        "max-clients": 1000, //最大允许的用户数 前端传入
        "verb": 3, //日志级别 0~11
        "data-ciphers": [ //加密算法套件
            "AES-256-GCM",
            "AES-128-GCM"
        ],
        "push_dns": "8.8.8.8", //推送DNS服务器地址给客户端
        "push_route_defalut": false, //是否让客户端将所有流量都通过VPN，如果为是则push_route将被忽略    
        "push_route": //客户端指定子网流量通过vpn
        [
            {
                "net": "192.168.1.0",
                "mask": "255.255.255.0"
            }
        ]
    }
}


12.6.	用户设置
	请求示例
POST /ccm/v1/manage/sslvpn/set-user HTTP/1.1 
Content-Length：ContentLength 
Content-Type:application/json;charset=UTF-8 
[
    {
        "uuid": "xx", //uuid 全局唯一
        "name": "用户名", //用户名 全局唯一
        "enable": true,
        "cert": "cert base64",
        "cert_DN":"证书dn",//新用户时可以为空字符串，后台根据证书解析填充该字段
        "phone_num": "13111111111" //可以空字符串 
        "bind_ip":"ipv4", //如果不启用访问控制，可以为空 为了做权限控制，dhcp上mac与ip绑定后，将ip与用户绑定
    }
]

	响应示例
{
"code":0,//错误码
"message":"code decribe msg",//错误描述
"result":{} 
}

12.7.	用户查询
	请求示例
POST /ccm/v1/manage/sslvpn/get-user HTTP/1.1 
Content-Length：ContentLength 
Content-Type:application/json;charset=UTF-8 
{
    
}
	响应示例
{
    "code": 0, //错误码
    "message": "code decribe msg", //错误描述
    "result": {
        "user": [
            {
                "uuid": "xx", //uuid 全局唯一
                "name": "用户名", //用户名 全局唯一
                "enable": true,
                "cert": "cert base64",
                "cert_DN": "证书dn", //新用户时可以为空字符串，后台根据证书解析填充该字段
                "phone_num": "13111111111", //可以空字符串 
                "bind_ip": "ipv4" //如果不启用访问控制，可以为空 为了做权限控制，dhcp上mac与ip绑定后，将ip与用户绑定
            }
        ]
    }
}


12.8.	资源设置
	请求示例
POST /ccm/v1/manage/sslvpn/set-resource  HTTP/1.1 
Content-Length：ContentLength 
Content-Type:application/json;charset=UTF-8 
[
    {
        "uuid": "xx", //uuid 全局唯一
        "name": "资源名称", //用户名 全局唯一
        "enable": true,
        "ip": "资源ip"//暂时只考虑ip4
    }
]
	响应示例
{
    "code":0,//错误码
    "message":"code decribe msg",//错误描述
    "result":{} 
}


12.9.	资源查询
	请求示例
POST /ccm/v1/manage/sslvpn/get-resource HTTP/1.1 
Content-Length：ContentLength 
Content-Type:application/json;charset=UTF-8 
{
    
}
	响应示例
{
    "code": 0, //错误码
    "message": "code decribe msg", //错误描述
    "result": {
        "resouce": [
            {
                "uuid": "xx", //uuid 全局唯一
                "name": "资源名称", //用户名 全局唯一
                "enable": true,
                "ip": "资源ip" //暂时只考虑ip4
            }
        ]
    }
}


12.10.	权限设置
	请求示例
POST /ccm/v1/manage/sslvpn/set-authority HTTP/1.1 
Content-Length：ContentLength 
Content-Type:application/json;charset=UTF-8 
{
    "enable": true, //全局开关， 启用时设置为true， 如果为false，则不启用访问控制
    "auth": [//启用访问控制时，权限规则
        {
            "user_uuid": "uuid 1", //uuid 全局唯一
            "resource_uuids": [ //可访问资源uuid的列表
                "uuid of resouce",
                "uuid of resouce"
            ]
        }
    ]
}
    

	响应示例
{
    "code":0,//错误码
    "message":"code decribe msg",//错误描述
    "result":{} 
}

12.11.	权限查询
	请求示例
POST /ccm/v1/manage/sslvpn/get-authority HTTP/1.1 
Content-Length：ContentLength 
Content-Type:application/json;charset=UTF-8 
{
    
}
	响应示例
{
    "code": 0, //错误码
    "message": "code decribe msg", //错误描述
    "result": {
        "enable": true, //全局开关， 启用时设置为true， 如果为false，则不启用访问控制
        "auth": [ //启用访问控制时，权限规则
            {
                "user": {//本条规则的用户信息
                    "uuid": "uuid of resouce",
                    "name": "11"
                },
                "resource": [ //可访问资源详情列表，为了在授权详情中，直接查看用户授权哪些资源，这里返回详情，而不只是uuid
                    {
                        "uuid": "uuid of resouce",
                        "name": "name of resouce",
                        "ip": "ip of resouce"
                    }
                ]
            }
        ]
    }
}





15.1.	证书密钥设置
	请求示例
POST /ccm/v1/manage/plugin/set-cert HTTP/1.1 
Content-Length：ContentLength 
Content-Type:application/json;charset=UTF-8 
{
        "ca": "base64 encode file", //文件内容的base64
        "cert": "base64 encode file", //文件内容的base64
        "key": "base64 encode file",//文件内容的base64
        "key_pwd":"1234",//私钥文件加密口令
        "crl":""//文件内容的base64
    }    

	响应示例
{
    "code":0,//错误码
    "message":"code decribe msg",//错误描述
    "result":{} 
}




15.2.	服务证书密钥查询
	请求示例
POST /ccm/v1/manage/iot/ set-motorstaus HTTP/1.1 
Content-Length：ContentLength 
Content-Type:application/json;charset=UTF-8 
{
    
}
    

	响应示例
{
    "code": 0, //错误码
    "message": "code decribe msg", //错误描述
    "result": {
        "ca": "base64 encode file", //文件内容的base64
        "cert": "base64 encode file", //文件内容的base64
        "crl":" base64 encode file "//文件内容的base64
    }
}


