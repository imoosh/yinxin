#!/bin/bash

## 1.生成自签名CA证书

# 1.1 生成私钥
openssl genrsa -out ca.key 2048

# 1.2 生成自签名的CA证书
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.pem

## 2.生成服务端证书

# 2.1 生成服务器的私钥
openssl genrsa -out server.key 2048

# 2.2 创建服务器的证书签名请求
openssl req -new -key ./server.key -out server.csr

# 2.3 使用自签名的CA证书签发服务器证书
openssl x509 -req -in ./server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem -days 3650 -sha256

# 3. 生成客户端证书

# 3.1 生成客户端的私钥 
openssl genrsa -out client-key.pem 2048

# 3.2 创建客户端的证书签名请求
openssl req -new -key client-key.pem -out client.csr

# 3.3 使用自签名的CA证书签发客户端证书
openssl x509 -req -days 3650 -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out client.pem
