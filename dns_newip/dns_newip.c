#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
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

#include "dns_struct.h"
#include "dns_table.h"
#include "dns_transtable.h"

#define DNS_DEFAULT_OUTERADDR "10.3.9.45"
#define DNS_LOCALADDR "127.0.0.1"
#define DNS_PORT 53

#define DNS_DEFAULT_FILE "dns_data.txt"

#define BUFFER_MAX_SIZE 512


bool checkargv(int argc, char *argv[], char *dnsFilePath, char *outerDNS);

void configSockAddr(struct sockaddr_in *name, char *addr);

int checkfdSet(int localSerSocket, int remoteSerSocket, fd_set *fdSet, struct timeval *timeout);

int main(int argc, char *argv[]) {

    printf("******************DNS: Progrm Start******************\n");
    char *dnsFilePath = DNS_DEFAULT_FILE;
    char *outerDNS = DNS_DEFAULT_OUTERADDR;
    if (!checkargv(argc, argv, dnsFilePath, outerDNS)) {
        printf("****************DNS: Arg Format Error****************\n");
        return 1;
    }

    struct id_transform_table *idTransTable = initIDTransTable();
    struct dns_table *dnsTable = importDomainTable(dnsFilePath);
    int localSerSocket = socket(AF_INET, SOCK_DGRAM, 0);
    int remoteSerSocket = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in remoteSerName, localSerName, clientName;
    socklen_t addrLength = sizeof(clientName);
    char currentDomain[DOMAIN_MAX_LEN];
    unsigned short qclass, qtype;

    configSockAddr(&remoteSerName, outerDNS);
    configSockAddr(&localSerName, DNS_LOCALADDR);
    if (bind(localSerSocket, (struct sockaddr *) &localSerName, sizeof(localSerName)) == -1) {
        printf("ERROR: Binding Local Port 53 failed.\n");
        printf("WARNS: Binding Failed: %s(errno: %d)\n", strerror(errno), errno);
        printf("******************DNS: Program Exit******************\n");
        return 1;
    } else {
        printf("STATE: Binding Local Port 53 succeed\n");
    }

    struct timeval timeout;
    fd_set fdSet;
    char sendBuf[BUFFER_MAX_SIZE];
    char recvBuf[BUFFER_MAX_SIZE];


    while (true) {
        int ret = checkfdSet(localSerSocket, remoteSerSocket, &fdSet, &timeout);

        if (ret < 0) {
            printf("ERROR: Select Error!\n");
            break;
        } else if (ret == 0) {
            printf("ERROR: Timeout\n");
            continue;
        }

        memset(recvBuf, 0, BUFFER_MAX_SIZE);
        memset(sendBuf, 0, BUFFER_MAX_SIZE);

        if (FD_ISSET(localSerSocket, &fdSet)) {
            int recvNum = recvfrom(localSerSocket, recvBuf, sizeof(recvBuf), 0, (struct sockaddr *) &clientName, &addrLength);
            if (recvNum == -1) {
                printf("WARNS: RecvFrom Failed: %s(errno: %d)\n", strerror(errno), errno);
            } else if (recvNum == 0) {
            } else {
                resolveRecv(recvBuf, recvNum, currentDomain, &qclass, &qtype);
                struct dns_table_item *findItem = findDnsItem(currentDomain, dnsTable);
                if (findItem == NULL) {
                    // not in dns table
                    unsigned short oldID;
                    memcpy(&oldID, recvBuf, sizeof(unsigned short));
                    unsigned short newID = htons(insertIDTransTable(idTransTable, ntohs(oldID), clientName, currentDomain));
                    memcpy(recvBuf, &newID, sizeof(unsigned short));

                    int send = sendto(remoteSerSocket, recvBuf, recvNum, 0,
                                       (struct sockaddr *) &remoteSerName, sizeof(remoteSerName));

                    if (send == -1) {
                        printf("WARNS: Sendto Failed: %s(errno: %d)\n", strerror(errno), errno);
                    }
                } else {
                    // in dns table
                    memcpy(sendBuf, recvBuf, recvNum);
                    int sendNum = recvNum;
                    if (findItem->type == ANSWER_TYPE_NULL) {
                        editDnsMessageFlag(sendBuf, 0x8183);
                    } else {
                        editDnsMessageFlag(sendBuf, 0x8180);
                        editDnsMessageAnswerRRs(sendBuf, 0x0001);
                        sendNum = addDNSMessageAnswer(sendBuf, sendNum, findItem);
                    }
                    int send = sendto(localSerSocket, sendBuf, sendNum, 0,
                                       (struct sockaddr *) &clientName, sizeof(clientName));

                    if (send == -1) {
                        printf("WARNS: Sendto Failed: %s(errno: %d)\n", strerror(errno), errno);
                    }
                }
            }
        }

        if (FD_ISSET(remoteSerSocket, &fdSet)) {
            int recvNum = recvfrom(remoteSerSocket, recvBuf, sizeof(recvBuf), 0,
                                  (struct sockaddr *) &remoteSerSocket, &addrLength);
            if (recvNum == -1) {
                printf("WARNS: RecvFrom Failed: %s(errno: %d)\n", strerror(errno), errno);
            } else if (recvNum == 0) {
            } else {
                unsigned short recvID;
                memcpy(&recvID, recvBuf, sizeof(unsigned short));
                unsigned short newID = htons(recvID);
                struct id_transform_item *item = deleteIDTransItem(newID, idTransTable);
                memcpy(recvBuf, &(item->oldID), 2);
                clientName = item->client;
                int send = sendto(localSerSocket, recvBuf, recvNum, 0,
                           (struct sockaddr *) &clientName, sizeof(clientName));
                if (send == -1) {
                    printf("WARNS: Sendto Failed: %s(errno: %d)\n", strerror(errno), errno);
                }
                free(item);
            }
        }
    }

    printf("******************DNS: Program Exit******************\n");
    return 0;
}

int checkfdSet(int localSerSocket, int remoteSerSocket, fd_set *fdSet, struct timeval *timeout) {
    timeout->tv_sec = 5000;
    timeout->tv_usec = 0;
    FD_ZERO(fdSet);
    FD_SET(remoteSerSocket, fdSet);
    FD_SET(localSerSocket, fdSet);
    int maxFds =
                remoteSerSocket > localSerSocket ? remoteSerSocket + 1 : localSerSocket + 1;
    int ret = select(maxFds, fdSet, NULL, NULL, timeout);
    return ret;
}

void configSockAddr(struct sockaddr_in *name, char *addr) {
    name->sin_family = AF_INET;
    name->sin_port = htons(DNS_PORT);
    name->sin_addr.s_addr = inet_addr(addr);
}

bool checkargv(int argc, char *argv[], char *dnsFilePath, char *outerDNS) {
    if (argc == 1) {
        printf("STATE: Use Default Remote Server: %s\n", outerDNS);
        printf("STATE: Use Default DNS File: %s\n", dnsFilePath);
        return true;
    } else if (argc == 3) {
        outerDNS = argv[1];
        dnsFilePath = argv[2];
        printf("STATE: Use Custom Remote Server: %s\n", outerDNS);
        printf("STATE: Use Custom DNS File: %s\n", dnsFilePath);
        return true;
    } else {
        return false;
    }
}