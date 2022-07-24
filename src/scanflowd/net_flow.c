#include "net_flow.h"

/* из за разного порядка байт по разному работает memcpy
 * функции перевода int/short -> массив char
 * size_t n - число переводимых элементов
*/

void memcpy_sh(char *dist, unsigned short *src, size_t n)
{
    size_t i, j = 0;
    for (i = 0; j < n; i+=2, j++) {
        dist[i + 1] = src[j] & 0xFF;
        dist[i] = (src[j] & 0xFF00) >> 8;
    }
}

void memcpy_int(char *dist, unsigned int *src, size_t n) // Решить проблему!!
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

void set_flow(struct flow *a, struct flow *b)
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
            fl_list->data[i].protocol = 0; // поток недействителен
        }
    }
}

void flow_update(struct flow *net_fl, const char *buff)
{
    struct ethhdr *eth = (struct ethhdr *) buff;
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
        net_fl->tcp_flags |= tcp->th_flags;
    }
}

unsigned short find_flow_id(struct flow_list *fl_list, struct flow *net_fl)
{
    // поиск потока в списке
    unsigned short i;
    for (i = 0; i < FL_LIST_SIZE; i++) {
        // если все 14 байт (т.е. само определения потоков) совпадают
        if (!memcmp(&net_fl, &fl_list->data[i], 14)) {
            return i;
        }
    }
    // невозможный индекс, означающий, то потока нет
    return 65500;
}


// создание элементов пакета

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
    for (unsigned short i = 0; i < data_size + 1; ++i) {
        nf_tpl[36 + i] = data[i];
    }

    return lenght;
}

unsigned short create_nf_data(char *nf_data, unsigned short template_ID,
                    struct flow *net_fl, struct exporter *sensor)
{
    char data[5], data_len;

    if (net_fl->protocol != 1) {
        memcpy(data, &net_fl->port_s_type, 2);
        memcpy(data + 2, &net_fl->port_d_code, 2);
        data_len = 4;
        if (net_fl->protocol == 6) {    // TCP
            data[4] = net_fl->tcp_flags;
            data_len++;
        }
    }
    else {
        memcpy(data, &net_fl->port_s_type, 1);
        memcpy(data + 1, &net_fl->port_d_code, 1);
        data_len = 2;
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
    nf_header[0] = (9 << 16) + count;   // версия + количество flow_sets
    nf_header[1] = sensor->sys_up_time;
    nf_header[2] = time(0);             // время отправки пакета
    nf_header[3] = sensor->sq_number;   // число пакетов
    nf_header[4] = source_id;
}

// создание пакетов NetFlow

unsigned short new_nf_tpl(char *nf_packet, struct exporter *sensor)
{
    unsigned short nf_tpl[42], bytes = 20, tpl_bytes = 0;

    // заголовок
    unsigned int nf_header[20];
    create_nf_header(nf_header, 3, sensor, sensor->source_id);
    memcpy_int(nf_packet, nf_header, 5);

    // ICMP
    tpl_bytes = create_nf_tpl(nf_tpl, 256, sizeof (sensor->if_name), 1);
    memcpy_sh(nf_packet + bytes, nf_tpl, tpl_bytes);
    bytes += tpl_bytes;

    // UDP
    tpl_bytes = 0;
    tpl_bytes = create_nf_tpl(nf_tpl, 257, sizeof (sensor->if_name), 17);
    memcpy_sh(nf_packet + bytes, nf_tpl, tpl_bytes);
    bytes += tpl_bytes;

    // TCP
    tpl_bytes = 0;
    tpl_bytes = create_nf_tpl(nf_tpl, 258, sizeof (sensor->if_name), 6);
    memcpy_sh(nf_packet + bytes, nf_tpl, tpl_bytes);

    return bytes + tpl_bytes;
}


unsigned int new_nf_data(char *nf_packet, struct flow *fl,
                         struct exporter *sensor)
{
    unsigned short bytes = 20, flow_sets = 0;
    unsigned int nf_header[20];
    create_nf_header(nf_header, flow_sets, sensor, sensor->source_id);
    memcpy_int(nf_packet, nf_header, 5);

    // запись по шаблонам
    if (fl->protocol == 1) {
        bytes += create_nf_data(nf_packet + 20, 256, fl, sensor);
    }
    else if (fl->protocol == 17) {
        bytes += create_nf_data(nf_packet + 20, 257, fl, sensor);
    }
    else if (fl->protocol == 6){
        bytes += create_nf_data(nf_packet + 20, 258, fl, sensor);
    }

    return bytes;
}