#include "safe_functions.h"

int create_raw_socket()
{
    int s = socket(AF_PACKET, SOCK_RAW, 0);
    if (s == -1) {
        perror("socket error!");
        exit(EXIT_FAILURE);
    }
    return s;
}

int create_udp_socket()
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == -1) {
        perror("socket error!");
        exit(EXIT_FAILURE);
    }
    return s;
}

void set_data_for_ifreq(int s, struct ifreq *if_req)
{
    if (ioctl(s, SIOCGIFINDEX, if_req, sizeof(if_req)) == -1) {
        perror("can't find device!");
        exit(EXIT_FAILURE);
    }
}

void bind_socket(const int s, const struct sockaddr *sa, socklen_t len)
{
    if (bind(s, sa, len) == -1) {
        perror("bind_socket error!");
        exit(EXIT_FAILURE);
    }
}
