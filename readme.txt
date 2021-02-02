客户端源程序client.c编译命令：gcc client.c -lssl -lcrypto -o client
服务器端源程序server.c编译命令：gcc server.c -lssl -lcrypto -o server
若要运行请修改head_server.h中的注册用户表IP地址，并将client.c中的服务器IP地址修改为自己机器的地址。