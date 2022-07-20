#include "net_flow.h"

// работа с памятью

/* из за разного порядка байт по разному работает memcpy
 * функции перевода int/short -> массив char
*/
void memcpy_sh(char *dist, unsigned short *src, size_t n)
{
    size_t i, j = 0;
    for (i = 0; j < n; i+=2, j++) {
        dist[i + 1] = src[j] & 0xFF;
        dist[i] = (src[j] & 0xFF00) >> 8;
    }
}

void memcpy_int(char *dist, unsigned int *src, size_t n)
{
    unsigned short a;
    size_t i, j = 0;
    for (i = 0; j < n; i+=4, j++) {
        a = (src[j] & 0xFFFF);
        memcpy_sh(dist + i + 2 , &a, 1);
        a = (src[j] & 0xFFFF0000) >> 16;
        memcpy_sh(dist + i, &a, 1);
    }
}


// управление списком потоков

void new_flow(struct flow *a, struct flow *b)
{
    a->protocol = b->protocol;
    a->tos = b->tos;
    a->ipv4_ident = b->ipv4_ident;
    a->ip_s = b->ip_s;
    a->ip_d = b->ip_d;
    a->port_s_type = b->port_s_type;
    a->port_d_code = b->port_d_code;
    a->tcp_flags = b->tcp_flags;
}

void flow_list_update(struct flow_list *fl_list, unsigned short f_inactive)
{
    unsigned short i;
    for (i = 0; i < FL_LIST_SIZE; i++) {
        if ((time(0) - fl_list->data[i].last_swtch) == f_inactive) {
            fl_list->data[i].protocol = 0; // убиваем поток
        }
    }
}

void flow_update(struct flow *net_fl, const char *buff)
{
    struct ethhdr *eth = (struct ethhdr *)buff;
    struct iphdr *ip = (struct iphdr *) buff + FRAME_HSIZE;

    net_fl->in_pkts++;
    net_fl->in_bytes += ip->tot_len;

    memcpy(net_fl->in_src_mac, eth->h_source, 6);
    memcpy(net_fl->in_dst_mac, eth->h_dest, 6);

    if (net_fl->first_swtch == 0) {
        net_fl->first_swtch = time(0);
    }
    net_fl->last_swtch = time(0);

    if (ip->protocol == 6) {
        struct tcphdr *tcp = (struct tcphdr *) buff + IP_HSIZE;
        net_fl->tcp_flags = net_fl->tcp_flags | tcp->th_flags;
    }
}

unsigned short find_flow_id(struct flow_list *fl_list, struct flow *net_fl)
{
    // поиск потока в списке
    unsigned short i;
    for (i = 0; i < FL_LIST_SIZE; i++) {
        // если все биты (т.е. само определения потоков) совпадают
        if (!memcmp(&net_fl, &fl_list->data[i], 14)) {
            return i;
        }
    }
    // невозможный индекс
    return 65500;
}


// создание пакета

unsigned short create_nf_tpl(unsigned short *nf_tpl, unsigned short template_ID,
                   unsigned short ifname_size, char proto)
{
    // для шаблона
    unsigned short field_count = 0;
    unsigned short data[6];

    if (proto == 1) {
        // ICMP
        data[0] = 32;   data[1] = 2;    // ICMP_TYPE icmp [type| code] 32bit
        field_count++;
    }
    else if (proto == 6) {
        // TCP
       data[0] = 7;     data[1] = 2;    // L4_SRC_PORT
       data[2] = 11;    data[3] = 2;    // L4_DST_PORT
       data[4] = 6;     data[5] = 1;    // TCP_FLAGS
       field_count += 3;
    }
    else {
        // UDP
        data[0] = 7;     data[1] = 2;    // L4_SRC_PORT
        data[2] = 11;    data[3] = 2;    // L4_DST_PORT
        field_count += 2;
    }

    unsigned short data_size = field_count * 2;
    field_count += 16;
    unsigned short lenght = (field_count + 2) * 4;

        nf_tpl[0] = 0; nf_tpl[1] = lenght,
        nf_tpl[2] = template_ID; nf_tpl[3] = field_count,
        // все что 4 байта
        nf_tpl[4] = 1; nf_tpl[5] = 4;    // IN_BYTES
        nf_tpl[6] = 2; nf_tpl[7] = 4;    // IN_PKTS
        nf_tpl[8] = 3; nf_tpl[9] = 4;    // FLOWS
        nf_tpl[10] = 21; nf_tpl[11] = 4;    // LAST_SWITCHED
        nf_tpl[12] = 22; nf_tpl[13] = 4;    // FIRST_SWITCHED
        nf_tpl[14] = 8; nf_tpl[15] = 4;    // IPV4_SRC_ADDR
        nf_tpl[16] = 12; nf_tpl[17] = 4;    // IPV4_DST_ADDR
        // все что 2 байта и т.д.
        nf_tpl[18] = 36; nf_tpl[19] = 2;    // FLOW_ACTIVE_TIMEOUT
        nf_tpl[20] = 37; nf_tpl[21] = 2;    // FLOW_INACTIVE_TIMEOUT
        nf_tpl[22] = 10; nf_tpl[23] = 2;    // INPUT_SNMP
        nf_tpl[24] = 54; nf_tpl[25] = 2;    // IPV4_IDENT

        nf_tpl[26] = 5; nf_tpl[27] = 1;    // SRC_TOS
        nf_tpl[28] = 4; nf_tpl[29] = 1;    // PROTOCOL
        // MAC
        nf_tpl[30] = 56; nf_tpl[31] = 6;    // IN_SRC_MAC
        nf_tpl[32] = 57; nf_tpl[33] = 6;    // IN_DST_MAC

        nf_tpl[34] = 82; nf_tpl[35] = ifname_size;  // IF_NAME

    // дописание в зависимости от протокола
    memcpy(nf_tpl + 4 + field_count * 2, data, data_size);

    return lenght;
}

unsigned short create_nf_data(char *nf_data, unsigned short template_ID,
                    struct flow *net_fl, struct exporter *sensor)
{
    char data[5], data_len = 4;

    memcpy(data, &net_fl->port_s_type, 2);
    memcpy(data + 2, &net_fl->port_s_type, 2);

    if (net_fl->protocol == 6) {    // TCP
        data[4] = net_fl->tcp_flags;
        data_len++;
    }

    unsigned int d_32[7] = {
        // все что 4 байта
        net_fl->in_bytes,
        net_fl->in_pkts,
        sensor->flows,
        net_fl->last_swtch,
        net_fl->first_swtch,
        net_fl->ip_s,
        net_fl->ip_d
    };

    unsigned short d_16[4] = {
        // все что 2 байта и т.д.
        sensor->f_active,
        sensor->f_inactive,
        sensor->input_snmp,
        net_fl->ipv4_ident
    };

    unsigned char d_8[2] = {
        net_fl->tos,
        net_fl->protocol
    };

    // IF_NAME
    unsigned short if_name_size = sizeof(sensor->if_name);

    unsigned short lenght = 4 + 28 + 8 + 2 + 12 + if_name_size + data_len;

    memcpy_sh(nf_data, &template_ID, 1);
    memcpy_sh(nf_data + 2, &lenght, 1);
    memcpy_int(nf_data + 4, d_32, 7);
    memcpy_sh(nf_data + 32, d_16, 4);
    memcpy(nf_data + 40, d_8, 2);
    memcpy(nf_data + 42, net_fl->in_src_mac, 6);
    memcpy(nf_data + 48, net_fl->in_dst_mac, 6);

    memcpy(nf_data + 54, sensor->if_name, if_name_size);
    memcpy(nf_data + 54 + if_name_size, data, data_len);

    return lenght;
}

void create_nf_header(unsigned int *nf_header, unsigned short count,
                      struct exporter *sensor, unsigned int source_id)
{
    // заголовок пакета
    nf_header[0] = (9 << 16) + count;   // версия + количество flow_sets
    nf_header[1] = sensor->sys_up_time;
    nf_header[2] = time(0);             // время отправки пакета
    nf_header[3] = sensor->sq_number;   // число пакетов
    nf_header[4] = source_id;           // номер потока?
}


// создание NetFlow пакета
unsigned int new_nf_pocket(char *nf_packet, struct flow_list *fl_list,
                         struct exporter *sensor)
{
    unsigned short bytes = 20, tpl_bytes = 0, flow_sets = 0;
    unsigned short i;

    unsigned short nf_tpl[42];      // 36 + 6 для наибольшого протокола
    // шаблоны
    for (i = fl_list->last_send; i < fl_list->free_id; i++) {
        tpl_bytes = create_nf_tpl(nf_tpl, 256 + i, sizeof (sensor->if_name),
                               fl_list->data[i].protocol);

        // bytes используется как смещение на размеры шаблонов + заголовок
        memcpy_sh(nf_packet + bytes, nf_tpl, tpl_bytes);
        bytes += tpl_bytes;
        flow_sets++;
    }

    // данные
    for (i = 0; i < fl_list->free_id; i++) {
        if (fl_list->data[i].protocol > 0) { // поток жив
            bytes += create_nf_data(nf_packet + bytes, 256 + i,
                                    &fl_list->data[i], sensor);
            flow_sets++;
        }
    }

    unsigned int nf_header[20];
    create_nf_header(nf_header, flow_sets, sensor,
                     sensor->source_id);
    memcpy_int(nf_packet, nf_header, 5);

    return bytes;
}


/*
 * NetFlow Version 9 Export Packet Example
 * Заголовок
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Version = 9               |          Count = 7            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           sysUpTime                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           UNIX Secs                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Sequence Number                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           Source ID                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Шаблон
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |       FlowSet ID = 0          |      Length = 28 bytes        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |       Template ID 256         |       Field Count = 5         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     IP_SRC_ADDR = 8           |       Field Length = 4        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     IP_DST_ADDR = 12          |       Field Length = 4        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     IP_NEXT_HOP = 15          |       Field Length = 4        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |       IN_PKTS = 2             |       Field Length = 4        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |       IN_BYTES = 1            |       Field Length = 4        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Данные
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |       FlowSet ID = 256        |          Length = 64          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          198.168.1.12                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          10.5.12.254                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          192.168.1.1                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             5009                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                            5344385                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          192.168.1.27                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           10.5.12.23                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          192.168.1.1                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                              748                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             388934                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          192.168.1.56                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           10.5.12.65                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           192.168.1.1                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                               5                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                              6534                             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
