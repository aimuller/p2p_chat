#include "head_server.h"
int main(){
    //涉及的变量声明
    int listen_sd;
    int sd;
    int i, r;
    struct sockaddr_in sa_cli;
    socklen_t client_len;

    //初始化连接表
    for(i = 0; i < SOCK_MAX; i++){
        table[i].flag = 0;
    }

    SSL_CTX* ctx = new_SSL_CTX();
    listen_sd = setupTCPServer();
    client_len = sizeof(sa_cli);
    while(1){
		
        fd_set readFDSet;
        FD_ZERO(&readFDSet);
        FD_SET(listen_sd, &readFDSet);
        for(i = 0; i < SOCK_MAX; i++){
			if(table[i].flag){
            	FD_SET(table[i].sd, &readFDSet);
			}
        }
        select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);
        if (FD_ISSET(listen_sd, &readFDSet)){  //又有一个新的客户端请求连接
			if(sock_num >= SOCK_MAX)  //连接已达最大上限
				continue;
			printf ("\n================================================================================\n");
			printf("新的客户端接入，连接信息如下:\n");
			sd = accept (listen_sd, (struct sockaddr*) &sa_cli, &client_len);
			CHK_ERR(sd, "accept");
			//inet_ntoa()函数将网络顺序地址转化为点分十进制地址
			printf ("Connection from %s, port %x\n", inet_ntoa(sa_cli.sin_addr), sa_cli.sin_port);
			SSL *ssl = SSL_new (ctx);	CHK_NULL(ssl);
			SSL_set_fd (ssl, sd);
			err = SSL_accept (ssl);	CHK_SSL(err);
			printf ("SSL connection using %s\n\n", SSL_get_cipher (ssl));
			if(!verify_cert(ssl)){
			  fprintf(stderr,"Client does not have certificate.\n");
			  exit(6);
			}
			for(i = 0; i < SOCK_MAX; i++){ //从会话表中找到一个可用的表项创建新的会话
			  if(table[i].flag == 0)
				  break;
			}
			//为新的客户端填充会话表信息
			table[i].flag = 1;
			table[i].sd = sd;
			table[i].net_addr = sa_cli.sin_addr.s_addr;
			table[i].ssl = ssl;
			sock_num++;
			//根据IP地址，从注册表中找到上线的帐号,将上线标记设置为1
			for(r = 0; r < SOCK_MAX; r++){
				if(inet_addr(user_table[r].net_addr) == table[i].net_addr){
					user_table[r].online = 1;
					strcpy(table[i].username, user_table[r].username);
					break;
				}
			}
			update_list();
			continue;
		}
		for(i = 0; i < SOCK_MAX; i++){
            if (table[i].flag && FD_ISSET(table[i].sd, &readFDSet)){
				int  len = 0;
				char buff[BUFF_MAX];
				bzero(buff, BUFF_MAX);
				len = SSL_read(table[i].ssl, buff, sizeof(buff));
				if(len <= 0){
					//根据IP地址，从账号表中找到下线的帐号,将上线标记设置为0
					for(r = 0; r < SOCK_MAX; r++){
						if(inet_addr(user_table[r].net_addr) == table[i].net_addr){
							user_table[r].online = 0;
							break;
						}
					}
					puts("One Client Over!\n");
					table[i].flag = 0;
					table[i].sd = 0;
					bzero(table[i].username, sizeof(table[i].username));
					table[i].net_addr = 0;
					table[i].ssl = NULL;
					sock_num--;
					close(table[i].sd);
					update_list();			

					continue;
				}
				else{
					buff[len] = '\0';
					if(strcmp(buff, "hello") == 0){
						len = SSL_write(table[i].ssl, online_user, sizeof(USER) * sock_num);			
					}
					else{
						int j, k;
						char name[16];
						bzero(name, 16);
						for(j = 3; j < len; j++){
							if(buff[j] == ':')
								break;
						}
						memcpy(name, buff + 3, j - 3);
						for(k = 0; k < SOCK_MAX; k++){
							if(table[k].flag && strcmp(table[k].username, name) == 0){
								len = SSL_write(table[k].ssl, table[i].username, sizeof(table[i].username));
								len = SSL_write(table[k].ssl, buff + j, sizeof(buff));
								break;
							}
						}
					}
				}
            }
        }
    }
    
	close(listen_sd);
	return 0; 
}

//初始化TCP服务端
int setupTCPServer(){
  /* Prepare TCP socket for receiving connections */
    struct sockaddr_in sa_server;
    int listen_sock;

    listen_sock= socket(AF_INET, SOCK_STREAM, 0); CHK_ERR(listen_sock, "socket");
    memset (&sa_server, '\0', sizeof(sa_server));
    sa_server.sin_family      = AF_INET;
    sa_server.sin_addr.s_addr = INADDR_ANY;
    sa_server.sin_port        = htons (11111);
    int err = bind(listen_sock, (struct sockaddr*)&sa_server, sizeof(sa_server));
    CHK_ERR(err, "bind");
    err = listen(listen_sock, 5);
    CHK_ERR(err, "listen");
    return listen_sock;
}

//初始化SSL，并创建一个并返回SSL上下文
SSL_CTX *new_SSL_CTX(){
  SSL_CTX* ctx;
  SSL_METHOD *meth;
  SSL_load_error_strings();
  SSLeay_add_ssl_algorithms();
  meth = (SSL_METHOD *) SSLv23_server_method();
  ctx = SSL_CTX_new (meth);
  if (!ctx) {
    ERR_print_errors_fp(stderr);
    exit(2);
  }
  SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL); /* whether verify the certificate */
  SSL_CTX_load_verify_locations(ctx,CACERT,NULL);
  if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(3);
  }
  if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(4);
  }
  if (!SSL_CTX_check_private_key(ctx)) {
    fprintf(stderr,"Private key does not match the certificate public key\n");
    exit(5);
  }
  return ctx;
}

//从ssl中获取client证书信息，并对client的证书进行验证
int verify_cert(SSL *ssl){
    X509*    client_cert;
    char*    str;
    client_cert = SSL_get_peer_certificate (ssl);
    if (client_cert != NULL) {
		printf("客户端证书验证通过，证书信息如下: \n");
        printf ("Client certificate:\n");
        str = X509_NAME_oneline (X509_get_subject_name (client_cert), 0, 0);
        CHK_NULL(str);
        printf ("subject: %s\n", str);
        OPENSSL_free (str);

        str = X509_NAME_oneline (X509_get_issuer_name  (client_cert), 0, 0);
        CHK_NULL(str);
        printf ("issuer: %s\n", str);
		printf ("================================================================================\n\n");
        OPENSSL_free (str);
		
        X509_free (client_cert);
        return 1;
     }
     else
        return 0;
}

int update_list(){
	int len, r, t = 0;
	bzero(online_user, sizeof(USER) * SOCK_MAX);
	bzero(flag, sizeof(int) * SOCK_MAX);
	
	//将在线的用户信息发给客户端
	for(r = 0; r < SOCK_MAX; r++){
		if(user_table[r].online){
			flag[r] = 1;
		    memcpy(&online_user[t], &user_table[r], sizeof(USER));
		    t++;
		}
	}
	
	//
	if(memcmp(flag, last_flag, sizeof(int) * SOCK_MAX) == 0)
		return 0;
	
	// print online list
	printf("\n-----------------------------------------------\n");
	printf("Update Online List: \n");
	for(r = 0; r < t; r++){
		printf("%s	%s\n", online_user[r].username, online_user[r].net_addr);
	}
	printf("-----------------------------------------------\n");

	memcpy(last_flag, flag, sizeof(int) * SOCK_MAX);
	for(r = 0; r < SOCK_MAX; r++){
		if(table[r].flag){
			len = SSL_write(table[r].ssl, "update", sizeof("update"));
			len = SSL_write(table[r].ssl, online_user, sizeof(USER) * t);
		}
	}

	return 1;
}

