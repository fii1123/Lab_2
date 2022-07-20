#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <unistd.h>

#include "safe_functions.h"
#include "net_flow.h"

// обычно, максимальный размер ip пакета до 576
#define BUFF_SIZE 576

// общие данные
struct argum {
    int listening_sock;
    int collect_sock;
    char buff[BUFF_SIZE];
    struct sockaddr_in collector_sa;
    struct exporter sensor;
    struct flow_list fl_list;
};

void *listening_thread(void *argum)
{
    struct argum *a = argum;
    struct flow net_fl;
    unsigned short flow_id;
    unsigned int buff_len = sizeof(a->buff);

    puts("Listening...\nPress \'q\' for exit");

    while (1) {
        net_fl.in_bytes = recv(a->listening_sock, a->buff, buff_len, 0);

        struct iphdr *ip = (struct iphdr *) a->buff + FRAME_HSIZE;

        // проверка пакета и заполнение
        switch (ip->protocol) {
        case 1:
        case 6:
        case 17:
            net_fl.protocol = ip->protocol;
            net_fl.tos = ip->tos;
            net_fl.ipv4_ident = ip->id;
            net_fl.ip_s = ip->saddr;
            net_fl.ip_d = ip->daddr;
            if (ip->protocol == 1) {
                struct icmp6_hdr *icmp = (struct icmp6_hdr *) a->buff
                        + IP_HSIZE;
                net_fl.port_s_type = icmp->icmp6_type;
                net_fl.port_d_code = icmp->icmp6_code;
            }
            else {
                struct udphdr *udp = (struct udphdr *) a->buff + IP_HSIZE;
                net_fl.port_s_type = udp->source;
                net_fl.port_d_code = udp->dest;
            }

            // поиск потока
            flow_id = find_flow_id(&a->fl_list, &net_fl);
            if (flow_id == 65500){
                // потока нет
                flow_id = a->fl_list.free_id;
                new_flow(&a->fl_list.data[flow_id], &net_fl);
                // защита от переполнения
                if (a->fl_list.free_id < FL_LIST_SIZE - 1) {
                    a->fl_list.free_id++;
                }
            }

            // обновление потока
            flow_update(&a->fl_list.data[flow_id], a->buff);

            break;
        default:
            break;
        }
    }
}

void *secondary_tread(void *argum)
{
    struct argum *a = argum;
    struct sockaddr_in sa = a->collector_sa;
    char nf_packet[1500];   // пакет целиком, вообще максимум 1500 байт
    int bytes;
    int time_of_send = time(0);

    while (1) {
        // удаление неактивных потоков
        flow_list_update(&a->fl_list, a->sensor.f_inactive);

        // пришло время отправки
        if ((unsigned short)
                difftime(time(0), time_of_send) == a->sensor.f_active) {
            a->sensor.sq_number++;
            // необходимо проанализировать собранный пакет!
            bytes = new_nf_pocket(nf_packet, &a->fl_list, &a->sensor);

#define DEBUG
#ifdef DEBUG
            printf("{");
            for (int i = 0; i < bytes; ++i) {
                if (i % 4 == 0) {
                    printf("\n");
                }
                printf("%x ", nf_packet[i]);
            }
            puts("}");
#endif
            bytes = sendto(a->collect_sock, nf_packet, bytes, 0,
                   (struct sockaddr *) &sa, sizeof(sa));

            // для отправки новых потоков
            a->fl_list.last_send = a->fl_list.free_id - 1;
            // обнуление
            memset(nf_packet, 0, bytes);
            time_of_send = time(0);
        }
    }
}

int main (int argc, char **argv)
{

    if (argc < 2) {
        puts("scanerflowd [interface name (enp*s* ...)] [collector ip]:[port]");
        exit(EXIT_FAILURE);
    } 

    int listening_socket = create_raw_socket();
    int collect_socket = create_udp_socket();

    // определение индекса сетевого интерфейса
    struct ifreq if_req;
    strcpy(if_req.ifr_ifrn.ifrn_name, argv[1]);
    set_data_for_ifreq(listening_socket, &if_req);

    struct sockaddr_ll sa_ll = {
        .sll_family = AF_PACKET,
        .sll_pkttype = PACKET_OTHERHOST,
        .sll_protocol = htons(ETH_P_ALL),
        .sll_ifindex = if_req.ifr_ifindex
    };
    bind_socket(listening_socket, (struct sockaddr *) &sa_ll, sizeof(sa_ll));

    uint32_t ip;
    inet_pton(AF_INET, if_req.ifr_ifru.ifru_addr.sa_data, &ip);
    struct sockaddr_in sa_cl = {
        .sin_family = AF_INET,
        .sin_port = 9994,           // порт сенсора потумолчанию
        .sin_addr.s_addr = ip       // ip адрес сетевого интерфейса
    };
    bind_socket(collect_socket, (struct sockaddr *) &sa_cl, sizeof(sa_cl));

    // обработка адреса коллектора
    char *port_str = strchr(argv[2], ':');
    *port_str = 0;
    port_str++;
    inet_pton(AF_INET, argv[2], &ip);
    sa_cl.sin_port = htons(atoi(port_str)); // порт коллектор

    // подготовка потоков
    pthread_t list_thread_id, secd_thread_id;
    pthread_attr_t thr_attr;
    pthread_attr_init(&thr_attr);

    // аргументы для передачи в поток
    struct argum a = {
        .buff = {0},
        .listening_sock = listening_socket,
        .collect_sock = collect_socket,
        .collector_sa = sa_cl,
        .sensor = {
            .if_name = argv[1],
            .input_snmp = if_req.ifr_ifindex,   // если честно, я не до конца понял разницу
            .source_id = if_req.ifr_ifindex,    // между ними
            .f_active = 5,     // 60
            .f_inactive = 15,
            .flows = 0,
            .sq_number = 0,
            .sys_up_time = time(0)
        },
        .fl_list = {
            .data = {0},
            .free_id = 0,
            .last_send = 0
        }
    };

    // потоки
    pthread_create(&list_thread_id, &thr_attr, listening_thread, &a);
    pthread_create(&secd_thread_id, &thr_attr, secondary_tread, &a);

    while (!getchar()) {
// позже нужно будет придумать, как сделать через ctrl + c
    }

    pthread_cancel(list_thread_id);
    pthread_cancel(secd_thread_id);

    close(collect_socket);
    close(listening_socket);


    exit(EXIT_SUCCESS);
}

