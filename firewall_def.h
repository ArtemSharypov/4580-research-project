
#ifndef FIREWALL_DEF_H
#define FIREWALL_DEF_H

#include <sys/types.h>

#define ALL 0
#define UDP 1
#define TCP 2
#define ICMP 3

#define OUTGOING_PACKET 1
#define INGOING_PACKET 2

#define BLOCK 1
#define UNBLOCK 0

#define VALUE_NOT_SET 0

typedef struct firewall_policy 
{
    u32_t src_ip_addr;
    u32_t src_netmask;
    u32_t dest_ip_addr;
    u32_t dest_netmask;
    u32_t dest_port;
    u32_t src_port;
    int packet_type; // whether it's an ingoing or outgoing packet
    int action; // whether we should block or unblock
    int protocol; // to which protocol this policy applies to
} firewall_policy_t;

typedef struct policies
{
    firewall_policy_t policies[15];
    int num_policies;
} policies_t;

#endif
