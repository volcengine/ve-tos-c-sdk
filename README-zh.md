# 火山引擎对象存储服务 C SDK

## 版本
- 当前版本：2.1.0

## 开发环境
1. 安装 CMake 工具（建议 2.6.0 及以上版本），点击 [这里](http://www.cmake.org/download/) 下载，典型安装方式如下：
```bash
./configure
make
make install
```
2. 安装 libcurl（建议 7.32.0 及以上版本），点击 [这里](http://curl.haxx.se/download.html?spm=5176.doc32132.2.7.23MmBq) 下载，典型安装方式如下：
```bash
./configure
make
make install
```
3. 安装 apr（建议 1.5.2 及以上版本），点击 [这里](https://apr.apache.org/download.cgi?spm=5176.doc32132.2.9.23MmBq&file=download.cgi) 下载，典型安装方式如下：
```bash
./configure
make
make install
```
4. 安装 apr-util（建议 1.5.4 及以上版本），点击 [这里](https://apr.apache.org/download.cgi?spm=5176.doc32132.2.10.23MmBq&file=download.cgi) 下载，安装时需要指定— with-apr 选项，典型安装方式如下：
```bash
./configure --with-apr=/your/apr/install/path
make
make install
```
5. 安装 cJSON（建议 1.7.18 及以上版本），点击 [这里](https://github.com/DaveGamble/cJSON) 下载，典型安装方式如下：
```bash
./configure
make
sudo make install
```

### 安装 SDK
源码安装。从 [GitHub](https://github.com/volcengine/ve-tos-c-sdk) 下载源码，典型编译命令如下：
```bash
cmake .
make
make install
```

## SDK 初始化
### 初始化 SDK 运行环境
```c
int main(int argc, char *argv[])
{
    /* 程序入口处调用 tos_http_io_initialize 方法，这个方法内部会做一些全局资源的初始化，涉及网络，内存等部分 */
    if (tos_http_io_initialize(NULL, 0) != TOSE_OK) {
        exit(1);
    }

    /* 调用 TOS SDK 的接口上传或下载文件 */
    /* ... 用户逻辑代码，这里省略 */

    /* 程序结束前，调用 tos_http_io_deinitialize 方法释放之前分配的全局资源 */
    tos_http_io_deinitialize();
    return 0;
}
```

### 初始化请求选项
```c
    /* 等价于 apr_pool_t，用于内存管理的内存池，实现代码在 apr 库中 */
    tos_pool_t *pool;
    tos_client_t *client;
    
    /* 重新创建一个新的内存池，第二个参数是 NULL，表示没有继承自其它内存池 */
    tos_pool_create(&pool, NULL);
    
    /* 创建并初始化 client，这个参数内部主要包括 endpoint,access_key_id,acces_key_secret, curl 参数等全局配置信息
     * client 的内存是由 pool 分配的，后续释放掉 pool 后，client 的内存也相当于释放掉了，不再需要单独释放内存
     */
    client = tos_client_create(pool);
    client->config = tos_config_create(client->pool);
    
    /* tos_str_set 是用 char* 类型的字符串初始化 tos_string_t 类型*/
    tos_str_set(&client->config->endpoint, "<用户的Endpoint>");
    tos_str_set(&client->config->access_key_id, "<用户的SecretId>");
    tos_str_set(&client->config->access_key_secret, "<用户的SecretKey>");
    tos_str_set(&client->config->sts_token, "<用户的StsToken>");
    
    /* ctl 用于设置网络相关参数，例如超时时间等(如果不需要使用默认值，需要自行设置)*/
    client->ctl = tos_http_controller_create(client->pool, 0);
    // client->ctl->options->connect_timeout = 5; // connect timeout 5s, if not set default is 10s
    // client->ctl->options->socket_timeout = 60; // socket timeout 60s, if not set default is 120s
```

##  SDK 一般使用流程
1. 初始化 SDK。
2. 设置请求选项参数。
3. 设置 API 接口必需的参数。
4. 调用 SDK API 发起请求并获得请求响应结果。