/*
接受一个tcp请求，简简单单发送发送一个http响应报文
*/
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <string>

#include "assert.h"
using namespace std;

SSL_CTX *ctx = NULL;
bool InitSSL(const char *cacert, const char *key, const char *passwd) {
  // 初始化
  SSLeay_add_ssl_algorithms();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
  ERR_load_BIO_strings();

  // 我们使用SSL V3,V2
  assert((ctx = SSL_CTX_new(SSLv23_method())) != NULL);

  // 要求校验对方证书，这里建议使用SSL_VERIFY_FAIL_IF_NO_PEER_CERT，详见https://blog.csdn.net/u013919153/article/details/78616737
  //对于服务器端来说如果使用的是SSL_VERIFY_PEER且服务器端没有考虑对方没交证书的情况，会出现只能访问一次，第二次访问就失败的情况。
  SSL_CTX_set_verify(ctx, SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

  // 加载CA的证书
  // assert(SSL_CTX_load_verify_locations(ctx, cacert, NULL));
  // 加载自己的证书
  assert(SSL_CTX_use_certificate_chain_file(ctx, cacert) > 0);
  // assert(SSL_CTX_use_certificate_file(ctx, "cacert.pem", SSL_FILETYPE_PEM) >
  // 0); 加载自己的私钥
  SSL_CTX_set_default_passwd_cb_userdata(ctx, (void *)passwd);
  assert(SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) > 0);

  // 判定私钥是否正确
  assert(SSL_CTX_check_private_key(ctx));

  return true;
}

int main(int argc, char *argv[]) {
  string cacert = "cnlab.cert";
  string key = "cnlab.prikey";
  string passwd = "";
  if (!InitSSL(cacert.c_str(), key.c_str(), passwd.c_str())) {
    printf("init ssl error\n");
    return 0;
  }

  if (argc < 3) {
    printf("need filename ip-address port\n");
    return 1;
  }
  // ip地址
  char *ip = argv[1];
  //端口
  int port = atoi(argv[2]);
  //创建socket,ipv4.tcp
  int listenfd = socket(PF_INET, SOCK_STREAM, 0);
  if (listenfd == -1) {
    printf("Create socket error %d", errno);
    return 1;
  }
  //命名socket
  //创建ipv4地址
  struct sockaddr_in m_addr;
  bzero(&m_addr, sizeof(m_addr));
  m_addr.sin_family = AF_INET;
  inet_pton(AF_INET, ip, &m_addr.sin_addr);
  m_addr.sin_port = htons(port);
  //绑定
  int ret = bind(listenfd, (struct sockaddr *)&m_addr, sizeof(m_addr));
  if (ret == -1) {
    printf("Socket bind error %d", ret);
    return 1;
  }
  //监听
  ret = listen(listenfd, 100);
  if (ret == -1) {
    printf("Listen error %d", ret);
    return 1;
  }
  while (1) {
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    int new_con = accept(listenfd, (sockaddr *)&addr, &addrlen);
    if (new_con == -1) {
      printf("accept error, errno = %d", errno);
      continue;
    } else {
      printf("accept %d success\n", new_con);
    }
    // ssl
    SSL *ssl = SSL_new(ctx);
    if (ssl == NULL) {
      printf("ssl new wrong\n");
      return 0;
    }
    SSL_set_accept_state(ssl);
    //关联sockfd和ssl
    SSL_set_fd(ssl, new_con);

    int ret = SSL_accept(ssl);
    if (ret != 1) {
      printf("%s\n", SSL_state_string_long(ssl));
      printf("ret = %d, ssl get error %d\n", ret, SSL_get_error(ssl, ret));
    }

    //
    string html_file = "index.html";
    int fd = open(html_file.c_str(), O_RDONLY);
    struct stat file_stat;
    stat(html_file.c_str(), &file_stat);
    void *html_ =
        mmap(nullptr, file_stat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

    string buf_w =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=UTF-8\r\n"
        "Connection: close\r\n"
        "Date: Fri, 23 Nov 2018 02:01:05 GMT\r\n"
        "Content-Length: " +
        to_string(file_stat.st_size) +
        "\r\n"
        "\r\n";
    buf_w += (char *)html_;
    //把send换成SSL_write
    // printf("send %d bytes\n", send(new_con, (void*)buf_w.c_str(),
    // buf_w.size(), 0));
    printf("send %d bytes\n",
           SSL_write(ssl, (void *)buf_w.c_str(), buf_w.size()));
    munmap(html_, file_stat.st_size);

    //关闭
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(new_con);
  }

  SSL_CTX_free(ctx);
  return 0;
}
