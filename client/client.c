#include "head_client.h"
int err;

int main(int argc, char *argv[])
{
	int ch;
	bzero(plain, sizeof(plain));
	bzero(cipher, sizeof(cipher));
	printf("=============================\n");
	printf("1.Chat    2.History    0.Exit\n");
	printf("=============================\n");
	scanf("%d", &ch);
	if(ch == 2){
		load_history();
		return 0;
	}
	else if(ch != 1)
		return 0;
    int sd;
    SSL *ssl;

    sd = setupTCPClient("10.0.2.10", 11111);
    ssl = new_SSL(sd);

	printf ("\n================================================================================\n");
	printf("成功连接服务器，连接证书信息信息如下:\n");

    printf ("SSL connection using %s\n", SSL_get_cipher (ssl));
    if(!verify_cert(ssl)){
      fprintf(stderr,"Server does not have certificate.\n");
      exit(6);
    }
	
	while(1){
		fd_set readFDSet;
		FD_ZERO(&readFDSet);
		FD_SET(sd, &readFDSet);        //将sd加入监听集合readFDSet
		FD_SET(STDIN_FILENO, &readFDSet);     //将标准输入的文件描述符STDIN_FILENO加入readFDSet
		select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);  //开始监听
		if(FD_ISSET(sd, &readFDSet)){  //套接字收到消息
			int len;
			char name[32], buf[BUFF_MAX];
			bzero(name, sizeof(name));
			bzero(buf, sizeof(buf));
			len = SSL_read(ssl, name, sizeof(name));
			if(len <= 0)
				continue;
			buf[len] = '\0';
			if(strcmp(name, "update") == 0){
				get_online_list(ssl);
			}

			else{
				printf("%s", name);
				len = SSL_read(ssl, buf, sizeof(buf));
				buf[len] = '\0';
				printf("%s", buf);
				strcat(plain, name);
				strcat(plain, buf);
			}
		}
		if(FD_ISSET(STDIN_FILENO, &readFDSet)){ //
			char buf[BUFF_MAX];
			bzero(buf, sizeof(buf));
			int len;
			if(fgets(buf, BUFF_MAX, stdin) == NULL){
				printf("too many characters!\n");
				continue;
			}
			if(strcmp(buf, "bye\n") == 0){
				save_history();
				break;
			}
			else if(memcmp(buf, "to ", 3) == 0){
				strcat(plain, buf);
				len = SSL_write(ssl, buf, strlen(buf));
			}
			else{
				continue;			
			}
		}
	}

    close (sd);
    return 0;
}

//创建Socket客户端
int setupTCPClient(char *ip, int port){
  struct sockaddr_in sa;
  int sd;
  sd = socket (AF_INET, SOCK_STREAM, 0);       CHK_ERR(sd, "socket");

  memset (&sa, '\0', sizeof(sa));
  sa.sin_family      = AF_INET;
  sa.sin_addr.s_addr = inet_addr (ip);  	/* Server IP */
  sa.sin_port        = htons     (port);    /* Server Port number */

  err = connect(sd, (struct sockaddr*) &sa, sizeof(sa));
  CHK_ERR(err, "connect");

  return sd;
}

SSL *new_SSL(int sd){
    SSL_CTX* ctx;
	SSL *ssl;
    SSL_METHOD *meth;
    SSLeay_add_ssl_algorithms();
    meth = (SSL_METHOD *) SSLv23_client_method();
    SSL_load_error_strings();
    ctx = SSL_CTX_new (meth);  CHK_NULL(ctx);
    SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
    SSL_CTX_load_verify_locations(ctx,CACERT,NULL);

    if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(-2);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(-3);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        printf("Private key does not match the certificate public keyn");
        exit(-4);
    }
	ssl = SSL_new (ctx);	CHK_NULL(ssl);
    SSL_set_fd (ssl, sd);
    err = SSL_connect (ssl);	CHK_SSL(err);
    return ssl;
}

//从ssl中获取server证书信息，并对server的证书进行验证
int verify_cert(SSL *ssl){
    X509*    server_cert;
    char*    str;
    server_cert = SSL_get_peer_certificate (ssl);

    if (server_cert != NULL) {
        printf ("Server certificate:\n");
        str = X509_NAME_oneline (X509_get_subject_name (server_cert),0,0);
        CHK_NULL(str);
        printf ("subject: %s\n", str);
        OPENSSL_free (str);
        str = X509_NAME_oneline (X509_get_issuer_name  (server_cert),0,0);
        CHK_NULL(str);
        printf ("issuer: %s\n", str);
		printf("================================================================================\n\n");
        OPENSSL_free (str);
        X509_free (server_cert);
        return 1;
    }
    else
        return 0;
}


//接收服务器传输过来的用户列表
void get_online_list(SSL *ssl){
    online_num = 0;
    int  len;
    bzero(online_table, sizeof(USER) * SOCK_MAX);
    len = SSL_read (ssl, online_table, sizeof(USER) * SOCK_MAX);  CHK_SSL(len);
    if(len <= 0)	
		CHK_ERR(err, "server error");
	printf("\n-----------------------------------------------\n");
	printf("Update Online List: \n");
    for(int i = 1; i * sizeof(USER) <= len; i++){
        printf("%s  %s\n", online_table[i - 1].username, online_table[i - 1].net_addr);
        online_num++;
    }
	printf("-----------------------------------------------\n\n");
}


void save_history(){
	printf("是否加密保存聊天记录? \n");
	printf("1.Yes	2.NO\n");
	int choose;
	scanf("%d", &choose);
	if(choose == 1){
		char pwd[20], filename[16];
		int len = 0;
   		if ((strlen(plain) + 1) % AES_BLOCK_SIZE == 0)
        	len = strlen(plain) + 1;
    	else 
        	len = ((strlen(plain) + 1) / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
		printf("请设置口令\n");
		scanf("%s", pwd);
		if(aes_encrypt(plain, pwd, cipher, len)){
			printf("加密成功！请输入要保存的文件名：\n");
			scanf("%s", filename);
			FILE *fp = fopen(filename, "wb");
			fwrite(cipher, 1, len, fp);
			fclose(fp);
		}
	}
}

void load_history(){
	char pwd[20], filename[16];
	int len = 0;
	printf("请输入文件名：\n");
	scanf("%s", filename);
	printf("请输入口令\n");
	scanf("%s", pwd);
	printf("%s中的聊天记录如下:\n", filename);
	printf("---------------------------------------------\n");
	FILE *fp = fopen(filename, "rb");
	len = fread(cipher, 1, BUFF_MAX, fp);
	bzero(plain, BUFF_MAX);
	aes_decrypt(cipher, pwd, plain, len);
	puts(plain);
	fclose(fp);	
}

int aes_encrypt(char* in, char* key, char* out,int len){
    if(!in || !key || !out) return 0;
    unsigned char iv[AES_BLOCK_SIZE];//加密的初始化向量
    for(int i=0; i<AES_BLOCK_SIZE; ++i)//iv一般设置为全0,可以设置其他，但是加密解密要一样就行
        iv[i]=0;
    AES_KEY aes;
	while(strlen(key) < 16){
		strcat(key, "*");
	}
    if(AES_set_encrypt_key((unsigned char*)key, 128, &aes) < 0){
        return 0;
    }
    AES_cbc_encrypt((unsigned char*)in, (unsigned char*)out, len, &aes, iv, AES_ENCRYPT);
    return 1;
}

int aes_decrypt(char* in, char* key, char* out, int len){
    if(!in || !key || !out) return 0;
    unsigned char iv[AES_BLOCK_SIZE];//加密的初始化向量
    for(int i=0; i<AES_BLOCK_SIZE; ++i)//iv一般设置为全0,可以设置其他，但是加密解密要一样就行
        iv[i]=0;
    AES_KEY aes;
	while(strlen(key) < 16){
		strcat(key, "*");
	}
    if(AES_set_decrypt_key((unsigned char*)key, 128, &aes) < 0){
        return 0;
    }
    AES_cbc_encrypt((unsigned char*)in, (unsigned char*)out, len, &aes, iv, AES_DECRYPT);
    return 1;
}


