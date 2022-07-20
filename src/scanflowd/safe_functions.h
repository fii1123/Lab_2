#ifndef SAFE_FUNCTIONS_H
#define SAFE_FUNCTIONS_H

#include <stdio.h>
#include <stdlib.h>
// в данном файле содержатся функции с обработкой ошибок
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <net/if.h>

#include <features.h>           // Для версии glibc
#if __GLIBC__ >= 2 && __GLIBC_MINOR >= 1
#include <netpacket/packet.h>
#include <net/ethernet.h>       // Протоколы L2
#else
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>     // Протоколы L2
#endif

#include <pthread.h>

int create_raw_socket();

int create_udp_socket();

void set_data_for_ifreq(int s, struct ifreq *if_req);

void bind_socket(const int s, const struct sockaddr *sa, socklen_t len);

#endif // SAFE_FUNCTIONS_H
