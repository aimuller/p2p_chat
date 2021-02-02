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
#include <pthread.h>

#include <openssl/rsa.h>       /* SSLeay stuff */
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <fcntl.h>
#include <string.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>

/* define HOME to be dir for key and cert files... */
#define HOME "./"
/* Make these what you want for cert & key files */
#define CERTF  HOME "server.crt"
#define KEYF  HOME  "nopwd_server.key"
#define CACERT HOME "ca.crt"


#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }
#define BUFF_MAX 2048
#define SOCK_MAX 3  //客户端连接服务器的最大数量
int createTunDevice();
int setupTCPServer();
SSL_CTX *new_SSL_CTX();
int verify_cert(SSL *ssl);
int update_list();

typedef struct SOCK_TABLE{  //会话表结构定义
    int flag;  //当前表项是否可用
    int sd;		//记录sd
    SSL *ssl;  //记录SSL指针
    in_addr_t net_addr;  //客户端网络地址
    char username[16];
} SOCK_TABLE;


typedef struct USER{  //注册账户结构定义
    int id;
    int online;
    char username[16];
    char net_addr[32];
} USER;

//连接表
SOCK_TABLE table[SOCK_MAX];
USER user_table[SOCK_MAX] = {
    {1, 0, "Alice", "10.0.2.11"},
    {2, 0, "Bob", "10.0.2.10"},
    {3, 0, "Caro", "10.0.2.16"}
};
USER online_user[SOCK_MAX];
int sock_num = 0;  //当前连接数量
int flag[SOCK_MAX], last_flag[SOCK_MAX];
int err;


