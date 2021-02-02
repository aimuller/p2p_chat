#ifndef HEAD_CLIENT
#define HEAD_CLIENT

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <openssl/rsa.h>       /* SSLeay stuff */
#include <openssl/crypto.h>
#include <openssl/aes.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include <fcntl.h>
#include <string.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>

#define CERTF "client.crt"
#define KEYF "nopwd_client.key"
#define CACERT "ca.crt"


#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }
#define MAX(a,b) a>b?a:b;

#define BUFF_MAX 2048
#define SOCK_MAX 3  //客户端连接服务器的最大数量
#define AES_BITS 128
#define MSG_LEN 128


char plain[BUFF_MAX];
char cipher[BUFF_MAX];
char tmp[BUFF_MAX];
int cur_len = 0;
typedef struct USER{  //注册账户结构定义
    int id;
    int online;
    char username[16];
    char net_addr[32] ;
} USER;


USER online_table[SOCK_MAX];

int online_num = 0;

//创建Socket客户端
int setupTCPClient(char *ip, int port);

SSL *new_SSL(int sd);

//从ssl中获取server证书信息，并对server的证书进行验证
int verify_cert(SSL *ssl);

void get_online_list(SSL *ssl);

void save_history();

void load_history();

int aes_decrypt(char* in, char* key, char* out,int len);

int aes_encrypt(char* in, char* key, char* out,int len);

#endif // HEAD_CLIENT

