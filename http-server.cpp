#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <iostream>
#include <string>

#include "assert.h"
using namespace std;

char rev_buffer[1024];  //接收信息缓冲区
char filePath[128];     //网页文件路径

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

void *https_server(void *args) {
  string cacert = "cnlab.cert";
  string key = "cnlab.prikey";
  string passwd = "";
  if (!InitSSL(cacert.c_str(), key.c_str(), passwd.c_str())) {
    printf("init ssl error\n");
    return 0;
  } else {
    printf("HTTPS服务器初始化SSL成功\r\n");
  }
  // ip地址
  char *ip = (char *)"127.0.0.1";
  //端口
  int port = atoi("443");
  //创建socket,ipv4.tcp
  int listenfd = socket(PF_INET, SOCK_STREAM, 0);
  if (listenfd == -1) {
    printf("HTTPS服务器创建serverSocket失败\r\n");
    exit(-1);
  } else {
    printf("HTTPS服务器创建serverSocket成功\r\n");
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
    printf("HTTPS服务器套接字绑定失败\r\n");
    return NULL;
  } else {
    printf("HTTPS服务器套接字绑定成功\r\n");
  }
  //监听
  ret = listen(listenfd, 100);
  if (ret == -1) {
    printf("Listen error %d", ret);
    return NULL;
  } else {
    printf("HTTPS服务器监听端口443中……\r\n");
  }
  while (1) {
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    int new_con = accept(listenfd, (sockaddr *)&addr, &addrlen);
    if (new_con == -1) {
      printf("[!]HTTPS服务器建立客户端连接失败\r\n");
      exit(-1);
    } else {
      printf("[+]HTTPS服务器成功建立客户端连接\r\n");
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
      printf("[!]ret = %d, ssl get error %d\n", ret, SSL_get_error(ssl, ret));
    }

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
    SSL_write(ssl, (void *)buf_w.c_str(), buf_w.size());
    munmap(html_, file_stat.st_size);
    printf("[+]状态码：200 OK\r\n");
    printf(
        "------------------------HTTPS服务器成功响应,返回了所请求的HTML信息！--"
        "----------------------\n");

    //关闭
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(new_con);
  }

  SSL_CTX_free(ctx);
  return 0;
}

/**
 * 主要步骤：
 * 1.初始化网络库
 * 2.创建socket
 * 3.绑定IP地址和端口号
 * 4.监听连接
 * 5.接收连接
 * 6.处理连接请求
 * 7.关闭连接，关闭网络库
 **/

void *http_server(void *args) {
  struct sockaddr_in serverAddr;
  //============================================================================
  // 2.创建socket
  // para1:指定IP协议  AF_INET -> IPV4  AF_INET6 -> IPV6
  // para2:数据传输格式  常用的有两种：流式传输（TCP）  数据包传输（UDP）
  // para3:传输协议：
  int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
  if (serverSocket == -1) {
    printf("HTTP服务器创建serverSocket失败\r\n");
    exit(-1);
  } else {
    printf("HTTP服务器创建serverSocket成功\r\n");
  }

  //============================================================================
  // 3.绑定IP地址和端口号(对于服务器是绑定，对于客户端是连接)
  // para1:  指定socket
  // para2:  IP地址和端口号
  // para3:  para2的长度

  // SOCKADDR_IN serverAddr;
  memset(&serverAddr, 0, sizeof(struct sockaddr_in));
  serverAddr.sin_family = AF_INET;  //必须和创建socket时一样
  serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
  serverAddr.sin_port =
      htons(80);  //此处涉及到大端存储和小端存储    一般计算机上都是小端的
                  //网络上一般都是大端的  所以需要将本地字节序转为网络字节序
  int ret;
  ret = bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr));
  if (ret == -1) {
    printf("HTTP服务器套接字绑定失败\r\n");
    exit(-1);
  } else {
    printf("HTTP服务器套接字绑定成功\r\n");
  }

  //============================================================================
  // 4.监听连接

  listen(serverSocket, 10);
  printf("HTTP服务器监听端口80中……\r\n");

  //============================================================================
  // 5.接收连接
  while (1) {
    struct sockaddr_in clientAddr;
    socklen_t len_clientAddr = sizeof(clientAddr);
    int clientSocket =
        accept(serverSocket, (struct sockaddr *)(&clientAddr), &len_clientAddr);
    if (clientSocket == -1) {
      printf("[!]HTTP服务器建立客户端连接失败\r\n");
      exit(-1);
    } else {
      printf("[+]HTTP服务器成功建立客户端连接\r\n");
    }

    // 6.处理连接请求
    //从clientSocket接受数据

    ret = recv(clientSocket, rev_buffer, sizeof(rev_buffer), 0);
    // printf("The return of recv is:%d\r\n", ret);

    if (ret <= 0) {
      printf("[!]接收来自客户端的数据失败\r\n");
      printf("重新进入等待连接状态......\r\n");
      close(clientSocket);
      continue;
      // exit(-1);
    } else {
      printf("[+]HTTP服务器成功接收来自客户端的数据！\r\n");
      printf("%s\r\n", rev_buffer);
    }
    截取其中的uri字段
    char *p = strtok(rev_buffer, " ");
    int i = 0;
    while (i < 1) {
      p = strtok(NULL, " ");
      i = i + 1;
    }
    char *url = strtok(p, "/");
    //给客户发送网页	后续可以根据具体请求，转向不同页面
    strcpy(filePath, "dir/index.html");
    std::cout << "url:" << filePath << '\n';

    ret = access(filePath,
                 0);  // 0 代表判断文件是否存在  如果存在返回0 否则返回-1
    if (ret != 0) {
      //未找到文件
      char sendBuf[1024] = {0};

      sprintf(sendBuf, "HTTP/1.1 404 NOT FOUND\r\n");
      send(clientSocket, sendBuf, strlen(sendBuf), 0);

      sprintf(sendBuf, "Content-type:text/html\r\n");
      send(clientSocket, sendBuf, strlen(sendBuf), 0);

      sprintf(sendBuf, "\r\n");
      send(clientSocket, sendBuf, strlen(sendBuf), 0);
      printf("[!]状态码：404 NOT FOUND\r\n");
      printf(
          "------------------------HTTP服务器成功响应！------------------------"
          "\r\n");
      // printf("sendBuf: %s\r\n", sendBuf);
    } else {
      //找到相关网页文件
      FILE *fs = fopen(filePath, "r");
      if (fs == NULL) {
        printf("打开网页文件失败\r\n");
        exit(-1);
      } else {
        char dataBuf[1024] = {0};

        sprintf(dataBuf, "HTTP/1.1 301 Moved Permanently\r\n");
        send(clientSocket, dataBuf, strlen(dataBuf), 0);

        sprintf(dataBuf, "Location:https://127.0.0.1/index.html\r\n");
        send(clientSocket, dataBuf, strlen(dataBuf), 0);

        sprintf(dataBuf, "\r\n");
        send(clientSocket, dataBuf, strlen(dataBuf), 0);

        while (fgets(dataBuf, 1024, fs) != NULL) {
          send(clientSocket, dataBuf, strlen(dataBuf), 0);
        }
        printf("[+]状态码：301 Moved Permanently\r\n");
        printf(
            "------------------------HTTP服务器成功响应！----------------------"
            "--\r\n");

        fclose(fs);
      }
    }
    close(clientSocket);  //发送完直接关闭  因为HTTP协议是无连接的
  }

  // 7.关闭连接，清理网络库

  close(serverSocket);
  return NULL;
}

int main() {
  pthread_t th1;
  pthread_t th2;
  int res;
  res = pthread_create(&th1, NULL, http_server, NULL);
  if (res == 0) {
    printf(
        "==================================HTTP服务器线程创建成功=============="
        "=========================\n");
  }
  res = pthread_create(&th2, NULL, https_server, NULL);
  if (res == 0) {
    printf(
        "==================================HTTPS服务器线程创建成功============="
        "=========================\n");
  }

  pthread_join(th2, NULL);
}