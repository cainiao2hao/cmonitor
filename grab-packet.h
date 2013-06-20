/* 
 * File:   grab-packet.h
 * Author: root
 *
 * Created on 2013年5月21日, 下午8:48
 */

#ifndef GRAB_PACKET_H
#define	GRAB_PACKET_H


#include <netinet/in.h>
#include <map>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <iostream>
#include <cstdlib>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <assert.h>
#include <vector>
using namespace std;

#define _ARP_ 1
#define _IP_ 2
#define _TCP_ 4
#define _UDP_ 8
#define _ICMP_ 16
#define _IP6_ 32
#define OUT 0
#define IN 1

struct EtherHdr
{
    u_int8_t ether_dhost[ETH_ALEN]; //48 bit mac address
    u_int8_t ether_shost[ETH_ALEN];
    uint16_t ether_type; //packet tyoe id field
    //0800 ip
    //0806 arp
    //86dd ipv6
};

struct IpHdr
{
    u_int8_t ver_ihl; //版本及数据包头长
    u_int8_t tos; //服务类型(较复杂)
    u_int16_t tot_len; //当前数据包总长，最多为64K
    u_int16_t id;
    u_int16_t frag_off;
    u_int8_t ttl; //生存时间，没经过一个路由，该值减一，为0丢弃
    u_int8_t protocol; //协议代码8位，表明使用该包裹的上层协议，如TCP=6，ICMP=1，UDP=17等。
    u_int16_t check;
    u_int32_t saddr; //源地址
    u_int32_t daddr; //目的地址
};

struct TcpHdr
{
    u_int16_t th_sport; //源端口号
    u_int16_t th_dport; //目的端口号
    u_int32_t th_seq;
    u_int32_t th_ack; //确认序号，TCP告诉接受者希望他下次接到数据包的第一个字节的序号。
    u_int8_t th_off; //data offset TCP头长度
    u_int8_t th_flags;
    u_int16_t th_win;
    u_int16_t th_sum;
    u_int16_t th_urp;
};

class local_addr
{
public:

    /* ipv4 constructor takes an in_addr_t */
    local_addr(in_addr_t m_addr)
    {
        addr = m_addr;
        sa_family = AF_INET;
        string = (char*) malloc(16);
        inet_ntop(AF_INET, &m_addr, string, 15);
    }
    char * string;
    in_addr_t addr;
    short int sa_family;
};

struct Total
{
    int in, out;
    bool vivid;

    Total()
    {
        in = out = 0;
        vivid = false;
    }
};

struct Packet
{
    char src_addr[20], des_addr[20], hash[60];
    u_int16_t direction, src_port, des_port;
    u_int32_t size;
};
void* begingrab(void *);
#endif	/* GRAB_PACKET_H */

