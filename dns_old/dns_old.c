#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <unistd.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>


// 宏定义: 对一些固定数据的定义
#define FORIEGN_DNS_ADDRESS "10.3.9.4"
#define DNS_PORT 53
#define BUF_SIZE 512
#define LENGTH 1024
#define NOTFOUND -1
#define TableMaxSize 600
#define IDTransformVectorMax 100

// MARK:: 0-1: 结构定义区
// 结构: DNS报文首部结构定义
typedef struct DNSHeader {
    unsigned short ID;
    unsigned short Flags;
    unsigned short QuestNum;
    unsigned short AnswerNum;
    unsigned short AuthorNum;
    unsigned short AdditionNum;
} Header;

// 结构: DNS域名解析表结构
typedef struct DNSAnalyseItem {
    char IP[16];        // IP地址
    char domain[LENGTH];   //域名
} DNSAnalyseItem;

typedef struct DNSAnalyseTable {
    int size;           // 表大小
    int currentSize;
    DNSAnalyseItem items[TableMaxSize];
} DNSAnalyseTable;

// 结构: ID转换表结构
typedef struct IDChange {
    unsigned short oldID; //原有ID
    bool done;            //标记是否完成解析
    struct sockaddr_in client;   //请求者套接字地址
    char domain[LENGTH];
} IDTransform;

typedef struct IDTransformVector {
    int size;           // 表大小
    IDTransform idTransform[IDTransformVectorMax];
} IDTransformVector;

// MARK:: 0-2: 全局变量定义区，注意使用时初始化
DNSAnalyseTable dnsTable;
IDTransformVector IDVector;
char url[LENGTH];                            //域名
time_t sys;                                  //系统时间
struct tm *sysTime;

// MARK:: 0-3: 函数定义区
// 函数定义: 用于输出因命令输入导致的错误
void commandLineArgumentFaultMessage();

// 函数定义: 用于获取域名解析表，并保存在指定的线性表中
int GetDomainTable(char *tablePath);

// 函数定义: 判断是否在表中找到DNS请求中的域名，找到返回下标，没找到返回NOTFOUND
int GetIPIndexOfDomain(char *domain);

//函数定义: 将请求ID转换为新的ID，并将信息写入ID转换表中
unsigned short GetNewID(unsigned short oID, struct sockaddr_in addr, bool ifDone,
                        char *domain);

//函数定义: 打印 时间 newID 功能 域名 IP
void DisplayInfo(unsigned short newID, int find, int mode, char *buffer, int length, unsigned short qclass,
                 unsigned short qtype);

//函数定义: 获取DNS请求中的域名
void GetUrl(char *recvBuf, int recvNum, unsigned short *qclass, unsigned short *qtype); //字符串、字符串长度

int main(int argc, char *argv[]) {
    // 各项参数
    int printLevel = 0;
    struct sockaddr_in serverName, clientName, localName;
    char sendBuf[BUF_SIZE];
    char recvBuf[BUF_SIZE];
    int iSend;
    socklen_t addrLength = sizeof(clientName);
    char *tablePath;// 用于保存配置文件路径
    char *outerDNS; // 用于保存外部DNSServer
    tablePath = "dnsrelay.txt";
    outerDNS = FORIEGN_DNS_ADDRESS;
    unsigned short qclass, qtype;
    printf("******************DNS: 程序开始运行******************\n");
    // MARK:: 1-程序执行模式检查
    // 模式：选择失败，参数列表错误
    if (argc < 1 || argc > 4 || argc == 2) {
        commandLineArgumentFaultMessage();
        printf("******************DNS: 程序执行完毕******************");
        exit(0);
    }
    // 模式：无调试信息输出
    // DNS服务器：202.106.0.20
    // 配置文件：当前目录下dnsrelay.txt
    if (argc == 1) {
        printLevel = 0;
        printf("STATE: 程序运行模式为: 无调试信息输出\n");
        printf("STATE: 使用默认服务器: %s\n", outerDNS);
        printf("STATE: 使用默认配置文件: %s\n", tablePath);
    }
    // 模式：调试信息级别2
    // DNS服务器：用户指定
    // 配置文件：当前目录下dnsrelay.txt
    if (argc == 3) {
        printLevel = 2;
        outerDNS = argv[2];
        printf("STATE: 程序运行模式为: 调试信息级别2\n");
        printf("STATE: 使用指定服务器: %s\n", outerDNS);
        printf("STATE: 使用默认配置文件: %s\n", tablePath);
    }
    // 模式：调试信息级别1
    // DNS服务器：用户指定
    // 配置文件：用户指定
    if (argc == 4) {
        printLevel = 1;
        outerDNS = argv[2];
        tablePath = argv[3];
        printf("STATE: 程序运行模式为: 调试信息级别1\n");
        printf("STATE: 使用指定服务器: %s\n", outerDNS);
        printf("STATE: 使用指定配置文件: %s\n", tablePath);
    }
    // MARK:: 2-开始读取文件
    dnsTable.size = 0;
    dnsTable.currentSize = 0;
    IDVector.size = 0;
    GetDomainTable(tablePath);

    // MARK:: 4-正式运行
    // 保存系统时间
    time(&sys);
    sysTime = localtime(&sys);
    //创建本地DNS和外部DNS套接字
    //创建本地DNS和外部DNS套接字
    int socketServer = socket(AF_INET, SOCK_DGRAM, 0);
    int socketLocal = socket(AF_INET, SOCK_DGRAM, 0);
    //设置本地DNS和外部DNS两个套接字
    localName.sin_family = AF_INET;
    localName.sin_port = htons(DNS_PORT);
    localName.sin_addr.s_addr = inet_addr("127.0.0.1");
    serverName.sin_family = AF_INET;
    serverName.sin_port = htons(53);
    serverName.sin_addr.s_addr = inet_addr(outerDNS);


    //绑定本地DNS服务器地址

    if (bind(socketLocal, (struct sockaddr *) &localName, sizeof(localName)) == -1) {
        printf("ERROR: Binding Local Port 53 failed.\n");
        printf("WARNS: Binding Failed: %s(errno: %d)\n", strerror(errno), errno);
        printf("******************DNS: 程序执行完毕******************");
        exit(1);
    } else {
        printf("STATE: Binding Local Port 53 succeed.\n");
    }


    // 本地DNS服务器的具体操作
    struct timeval timeout;
    fd_set fdSet; //套接字集合
    while (1) {
        timeout.tv_sec = 5000; // 5秒
        timeout.tv_usec = 0;
        FD_ZERO(&fdSet); //清空
        FD_SET(socketServer, &fdSet);
        FD_SET(socketLocal, &fdSet);
        int maxFds =
                socketServer > socketLocal ? socketServer + 1 : socketLocal + 1;
        int ret;
        ret = select(maxFds, &fdSet, NULL, NULL, &timeout);
        if (ret < 0) {
            printf("ERROR: Select Error!\n");
            break;
        } else if (ret == 0) {
            printf("ERROR: Timeout\n");
            continue;
        }
        memset(recvBuf, 0, BUF_SIZE);

        // 接受来自内部的报文请求
        if (FD_ISSET(socketLocal, &fdSet)) {

            int iRecv1 = recvfrom(socketLocal, recvBuf, sizeof(recvBuf), 0,
                                  (struct sockaddr *) &clientName, &addrLength);

            if (iRecv1 == -1) {
                printf("WARNS: RecvFrom Failed: %s(errno: %d)\n", strerror(errno), errno);
                continue;
            } else if (iRecv1 == 0) //接收的字符数为0
            {
                continue;

            } else {

                GetUrl(recvBuf, iRecv1, &qclass, &qtype);     //获取域名
                if (qtype != 1) {
                    unsigned short *oldID =
                            (unsigned short *) malloc(sizeof(unsigned short));
                    memcpy(oldID, recvBuf, sizeof(unsigned short));
                    unsigned short newID =
                            htons(GetNewID(ntohs(*oldID), clientName, false, url));
                    memcpy(recvBuf, &newID, sizeof(unsigned short));

                    //打印 时间 newID 功能 域名 IP
                    DisplayInfo(ntohs(newID), -2, printLevel, recvBuf, iRecv1, qclass, qtype);
                } else {
                    int find = GetIPIndexOfDomain(url); //在域名解析表中查找
                    char x[LENGTH];
                    strcpy(x, url);
                    if (find == NOTFOUND) //在域名解析表中没有找到
                    {
                        // 中继功能:转发
                        //转换ID,并将旧ID与ClientSocket存入IDVector
                        unsigned short *oldID =
                                (unsigned short *) malloc(sizeof(unsigned short));
                        memcpy(oldID, recvBuf, sizeof(unsigned short));
                        unsigned short newID =
                                htons(GetNewID(ntohs(*oldID), clientName, false, x));
                        memcpy(recvBuf, &newID, sizeof(unsigned short));

                        //打印 时间 newID 功能 域名 IP
                        DisplayInfo(ntohs(newID), find, printLevel, recvBuf, iRecv1, qclass, qtype);

                        //把recvBuf转发至指定的外部DNS服务器

                        iSend = sendto(socketServer, recvBuf, iRecv1, 0,
                                       (struct sockaddr *) &serverName, sizeof(serverName));

                        if (iSend == -1) {
                            printf("WARNS: Sendto Failed: %s(errno: %d)\n", strerror(errno), errno);
                            continue;
                        } else if (iSend == 0) {
                            continue;
                        }

                        free(oldID); //释放动态分配的内存
                    } else //在域名解析表中找到
                    {
                        //获取请求报文的ID
                        unsigned short *oldID =
                                (unsigned short *) malloc(sizeof(unsigned short));
                        memcpy(oldID, recvBuf, sizeof(unsigned short));
                        // 转换ID,并将旧ID与ClientSocket存入IDVector
                        unsigned short newID =
                                GetNewID(ntohs(*oldID), clientName, true, x);

                        //打印 时间 newID 功能 域名 IP
                        DisplayInfo(newID, find, printLevel, recvBuf, iRecv1, qclass, qtype);

                        //构造响应报文返回
                        memcpy(sendBuf, recvBuf, iRecv1); //拷贝请求报文

                        unsigned short sends;
                        unsigned long sendl;
                        //修改FLAG区
                        if (strcmp(dnsTable.items[find].IP, "0.0.0.0") == 0)
                            sends = htons(0x8183); //屏蔽功能：回答数为0
                        else
                            sends = htons(0x8180); //服务器功能：回答数为1
                        memcpy(&sendBuf[2], &sends, sizeof(unsigned short)); //修改标志域

                        //修改回答数域
                        if (strcmp(dnsTable.items[find].IP, "0.0.0.0") == 0)
                            sends = htons(0x0000); //屏蔽功能：回答数为0
                        else
                            sends = htons(0x0001); //服务器功能：回答数为1
                        memcpy(&sendBuf[6], &sends, sizeof(unsigned short));
                        int length = iRecv1;
                        if (strcmp(dnsTable.items[find].IP, "0.0.0.0") == 0) {

                        } else {
                            //构造DNS响应部分
                            // ANSWER NAME
                            sends = htons(0xc00c);
                            memcpy(&sendBuf[length], &sends, 2);
                            // TYPE
                            length += 2;
                            sends = htons(0x0001);
                            memcpy(&sendBuf[length], &sends, 2);
                            // CLASS
                            length += 2;
                            sends = htons(0x0001);
                            memcpy(&sendBuf[length], &sends, 2);
                            // TTL
                            length += 2;
                            sendl = htonl(0x000000ce);
                            memcpy(&sendBuf[length], &sendl, 4);
                            // RDLENGTH
                            length += 4;
                            sends = htons(0x0004);
                            memcpy(&sendBuf[length], &sends, 2);
                            // RDATA
                            length += 2;
                            //用inet_addr()把字符串形式的IP地址转换成unsigned
                            sendl = (unsigned long) inet_addr(dnsTable.items[find].IP);
                            memcpy(&sendBuf[length], &sendl, 4);
                            length += 4;
                        }


                        //发送响应报文
                        iSend = sendto(socketLocal, sendBuf, length, 0,
                                       (struct sockaddr *) &clientName, sizeof(clientName));
                        if (iSend == -1) {
                            printf("WARNS: Sendto Failed: %s(errno: %d)\n", strerror(errno), errno);
                            continue;
                        } else if (iSend == 0) {
                            continue;
                        }

                        free(oldID); //释放动态分配的内存
                    }
                }

            }

        }


        if (FD_ISSET(socketServer, &fdSet)) {
            // 接收来自外部DNS服务器的响应报文
            int iRecv2 = recvfrom(socketServer, recvBuf, sizeof(recvBuf), 0,
                                  (struct sockaddr *) &serverName, &addrLength);
            if (iRecv2 == -1) {
                printf("WARNS: RecvFrom Failed: %s(errno: %d)\n", strerror(errno), errno);
                continue;
            } else if (iRecv2 == 0) //接收的字符数为0
            {
                continue;
            }
            // ID转换

            unsigned short *newID =
                    (unsigned short *) malloc(sizeof(unsigned short));
            memcpy(newID, recvBuf, sizeof(unsigned short));
            int m = ntohs(*newID);
            unsigned short oldID = htons(IDVector.idTransform[m].oldID);
            memcpy(recvBuf, &oldID, sizeof(unsigned short));
            IDVector.idTransform[m].done = true;
            // 进行缓存
            char domainCache[LENGTH];
            strcpy(domainCache,IDVector.idTransform[m].domain);
            int nquery = ntohs(*((unsigned short*)(recvBuf + 4))), nresponse = ntohs(*((unsigned short*)(recvBuf + 6)));
            char* p = recvBuf + 12;
            char ip[16];
            int ip1, ip2, ip3, ip4;
            /* 从查询中读取url，但只记录最后一个url */
            for (int i = 0; i < nquery; i++)
            {
                while (*p > 0)
                    p += (*p) + 1;
                p += 5; /* Point to the next query */
            }
            for (int i = 0; i < nresponse; ++i)
            {
                if ((unsigned char)*p == 0xc0) /* 名称字段是指针 */
                    p += 2;
                else /* The name field is Url */
                {
                    while (*p > 0)
                        p += (*p) + 1;
                    ++p;
                }
                unsigned short resp_type = ntohs(*(unsigned short*)p);  /* Type */
                p += 10;

                if (resp_type == 1) /* Type A, the response is IPv4 address */
                {
                    ip1 = (unsigned char)*p++;
                    ip2 = (unsigned char)*p++;
                    ip3 = (unsigned char)*p++;
                    ip4 = (unsigned char)*p;
                    sprintf(ip, "%d.%d.%d.%d", ip1, ip2, ip3, ip4);
                    if(printLevel!=0){
                        printf("STATE: 缓存 Domain: %s\n",domainCache);
                        printf("STATE: 缓存 IP address : %d.%d.%d.%d\n", ip1, ip2, ip3, ip4);
                    }
                    // Cache保存
                    if(dnsTable.currentSize==TableMaxSize){
                        dnsTable.currentSize = dnsTable.size;
                    }
                    strcpy(dnsTable.items[dnsTable.currentSize].domain,domainCache);
                    strcpy(dnsTable.items[dnsTable.currentSize].IP,ip);
                    dnsTable.currentSize += 1;
                    /* Add record to cache */
                    break;
                }
            }

            //从ID转换表中获取发出DNS请求者的信息
            clientName = IDVector.idTransform[m].client;

            //把recvBuf转发至请求者处
            iSend = sendto(socketLocal, recvBuf, iRecv2, 0,
                           (struct sockaddr *) &clientName, sizeof(clientName));
            if (iSend == -1) {
                printf("WARNS: Sendto Failed: %s(errno: %d)\n", strerror(errno), errno);
                continue;
            } else if (iSend == 0) {
                continue;
            }

            free(newID); //释放动态分配的内存
        }
    }


    printf("******************DNS: 程序执行完毕******************");
    return 0;
}

// MARK:: 0-4: 函数实现区

// 函数实现: 用于输出因命令输入导致的错误
void commandLineArgumentFaultMessage() {
    printf("ERROR: 参数输入错误，程序运行失败\n");
    printf("POINT: 命令格式: dnsrelay [-d | -dd] [dns-server-ipaddr] [filename]\n");
}

// 函数实现: 用于获取域名解析表，并保存在指定的线性表中
int GetDomainTable(char *tablePath) {
    dnsTable.size = 0;
    dnsTable.currentSize = 0;
    FILE *tableFileText;
    if ((tableFileText = fopen(tablePath, "rt")) == NULL) {
        printf("STATE: 无法打开 %s 文件\n", tablePath);
        printf("******************DNS: 程序执行完毕******************");
        exit(0);
    }
    printf("STATE: 读取 %s 文件\n", tablePath);
    int i = 0;
    for (i = 0; i <= 999; i++) {
        if ((i % 2) == 0) {
            if (fscanf(tableFileText, "%s", dnsTable.items[i / 2].IP) != EOF)
                continue;
            else
                break;
        } else {
            if (fscanf(tableFileText, "%s", dnsTable.items[i / 2].domain) != EOF)
                continue;
            else
                break;
        }
    }
    dnsTable.size = i / 2;
    dnsTable.currentSize = dnsTable.size;
    printf("STATE: 共导入域名信息 %d 条\n", dnsTable.size);
    // 操作结束后关闭文件
    fclose(tableFileText);
    printf("STATE: 导入 %s 文件数据成功\n", tablePath);
    return dnsTable.size;
}

// 函数实现: 判断是否在表中找到DNS请求中的域名，找到返回下标，没找到返回NOTFOUND
int GetIPIndexOfDomain(char *domain) {
    int index = 0;
    int isFind = NOTFOUND;
    for (index = 0; index < dnsTable.currentSize; index++) {
        if (strcmp(dnsTable.items[index].domain, domain) == 0) {
            isFind = 1;
            break;
        }
    }
    if (isFind == 1)
        return index;

    else
        return NOTFOUND;
}


// 函数实现: 将请求ID转换为新的ID，并将信息写入ID转换表中
unsigned short GetNewID(unsigned short oID, struct sockaddr_in addr, bool ifDone,
                        char *domain) {
    strcpy(IDVector.idTransform[IDVector.size].domain, domain);
    if (IDVector.size == IDTransformVectorMax) {
        IDVector.size = 0;
    }
    IDVector.idTransform[IDVector.size].client = addr;
    IDVector.idTransform[IDVector.size].done = ifDone;
    IDVector.idTransform[IDVector.size].oldID = oID;
    IDVector.size += 1;
    return (unsigned short) (IDVector.size - 1); //以表中下标作为新的ID
}

// 函数实现: 获取DNS请求中的域名
void GetUrl(char *recvBuf, int recvNum, unsigned short *qclass, unsigned short *qtype) {
    char urlName[LENGTH];
    int i = 0, j, k = 0;
    memset(url, 0, LENGTH);
    memset(qclass, 0, sizeof(*qclass));
    memset(qtype, 0, sizeof(*qtype));
    unsigned short tmp;
    memcpy(&tmp, &(recvBuf[recvNum - 4]), 2);
    *qtype = ntohs(tmp);
    memcpy(&tmp, &(recvBuf[recvNum - 2]), 2);
    *qclass = ntohs(tmp);

    memcpy(urlName, &(recvBuf[sizeof(Header)]), recvNum - 16);
    // 获取请求报文中的域名表示
    int len = strlen(urlName);
    // 域名转换
    while (i < len) {
        if (urlName[i] > 0 && urlName[i] <= 63)
            for (j = urlName[i], i++; j > 0; j--, i++, k++)
                url[k] = urlName[i];

        if (urlName[i] != 0) {
            url[k] = '.';
            k++;
        }
    }
    url[k] = '\0';
}


// 函数实现: 打印 时间 newID 功能 域名 IP
void DisplayInfo(unsigned short newID, int find, int mode, char *buffer, int length, unsigned short qclass,
                 unsigned short qtype) {
    // 打印时间
    time(&sys);
    sysTime = localtime(&sys);
    if (mode == 0) {
        return;
    } else if (mode == 1) {
        // 打印转换后新的ID
        printf("$ID.%d\n", newID);
        printf("STATE: 当前时间: %02d:%02d:%02d  %04d.%02d.%02d\n", sysTime->tm_hour, sysTime->tm_min, sysTime->tm_sec,
               sysTime->tm_year - 100 + 2000, sysTime->tm_mon + 1, sysTime->tm_mday);
        // 分情况输出
        // 在表中没有找到DNS请求中的域名
        if (find == NOTFOUND) {
            printf("STATE: 模式: 中继功能\n");
            printf("STATE: 查询域名: %s\n", url);
        } // 在表中找到DNS请求中的域名
        else {
            if (strcmp(dnsTable.items[find].IP, "0.0.0.0") == 0) {
                //不良网站拦截
                printf("STATE: 模式: 屏蔽功能\n");
                printf("STATE: 屏蔽域名: %s\n", url);
            } else {
                //检索结果为普通IP地址，则向客户返回这个地址
                printf("STATE: 模式: 服务器功能\n");
                printf("STATE: 查询域名: %s\n", url);
                printf("STATE: IP地址: %s\n", dnsTable.items[find].IP);
            }
        }
    } else {
        // 打印转换后新的ID
        printf("$ID.%d\n", newID);
        printf("STATE: 当前时间: %02d:%02d:%02d  %04d.%02d.%02d\n", sysTime->tm_hour, sysTime->tm_min, sysTime->tm_sec,
               sysTime->tm_year - 100 + 2000, sysTime->tm_mon + 1, sysTime->tm_mday);
        // 分情况输出
        // 在表中没有找到DNS请求中的域名
        if (find == NOTFOUND) {
            printf("STATE: 模式: 中继功能\n");
            printf("STATE: 查询域名: %s\n", url);
            printf("STATE: QType: %u QClass: %u\n", qtype, qclass);
            printf("STATE: 数据: (大小=%d) ", length);
            for (int i = 0; i < length; i++) {
                printf("%.2x ", buffer[i]);
            }
            printf("\n");
        } // 在表中找到DNS请求中的域名
        else if (find==-2){
            printf("STATE: 模式: 无法响应 (非IPV4)\n");
            printf("STATE: 查询域名: %s\n", url);
            printf("STATE: QType: %u QClass: %u\n", qtype, qclass);
            printf("STATE: 数据: (大小=%d) ", length);
            for (int i = 0; i < length; i++) {
                printf("%.2x ", buffer[i]);
            }
            printf("\n");
        }
        else {
            if (strcmp(dnsTable.items[find].IP, "0.0.0.0") == 0) {
                //不良网站拦截
                printf("STATE: 模式: 屏蔽功能\n");

                printf("STATE: 屏蔽域名: %s\n", url);
                printf("STATE: 数据: (大小=%d) ", length);
                for (int i = 0; i < length; i++) {
                    printf("%.2x ", buffer[i]);
                }
                printf("\n");
            } else {
                //检索结果为普通IP地址，则向客户返回这个地址
                printf("STATE: 模式: 服务器功能\n");
                printf("STATE: 查询域名: %s\n", url);
                printf("STATE: IP地址: %s\n", dnsTable.items[find].IP);
                printf("STATE: 数据: (大小=%d) ", length);
                for (int i = 0; i < length; i++) {
                    printf("%.2x ", buffer[i]);
                }
                printf("\n");
            }
        }
    }
}