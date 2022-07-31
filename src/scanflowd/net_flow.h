#ifndef NET_FLOW_H
#define NET_FLOW_H

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/icmp6.h>
#include <time.h>

// заголовки ip и фрейма
#define FRAME_HSIZE 14
#define IP_HSIZE (FRAME_HSIZE + sizeof(struct iphdr))

// информация о сенсоре
struct exporter {
    unsigned int flows;         // число потоков

    // timeout
    unsigned short f_active;    // отправка данных каждые X sec
    unsigned short f_inactive;  // интервал неактивности
    unsigned short input_snmp;  // индекс сетевого интерфейса
    char *if_name;              // имя сетевого интерфейса

    // для заголовка
    unsigned int sys_up_time;   // время работы сенсера
    unsigned int source_id;     // индекс сетевого интерфейса
    unsigned int sq_number;     // число отправленных netflow пакетов
};

// поток netflow
struct flow {
    // определение потока
    char protocol;
    char tos;
    unsigned int ip_s;
    unsigned int ip_d;   
    unsigned short port_s_type; // порт отправителя или тип
    unsigned short port_d_code; // порт получателя или код

    // переменные потока
    unsigned int in_bytes;
    unsigned int in_pkts;

    unsigned int last_swtch;
    unsigned int first_swtch;

    char tcp_flags;

    // данные с последнего пакета
    unsigned int ipv4_ident;
    char in_src_mac[6];
    char in_dst_mac[6];
};

struct flow_list {
#define FL_LIST_SIZE 64
    struct flow data[FL_LIST_SIZE];
    unsigned short free_id;     // свободный id
};


// управление списком потоков

// присваивание потоку a определение потока b
void set_flow(struct flow *a, struct flow *b);

// обновление списка потоков
void flow_list_update(struct flow_list *fl_list, unsigned short f_inactive);

// обновление данных потока
void flow_update(struct flow *net_fl, const char *buff);

// поиск потока
unsigned short find_flow_id(struct flow_list *fl_list, struct flow *net_fl);


// создание пакетов

unsigned short new_nf_tpl(char *nf_packet, struct exporter *sensor);

unsigned int new_nf_data(char *nf_packet, struct flow *fl,
                         struct exporter *sensor);

#endif // NET_FLOW_H
