
#ifndef __FIREWALL_CONFIG_H__
#def __FIREWALL_CONFIG_H__

#define ALL 0
#define UDP 1
#define TCP 2
#define ICMP 3

typedef struct firewall_policy 
{
    u32_t *src_ip_addr;
    u32_t *src_netmask;
    u32_t *dest_ip_addr;
    u32_t *dest_netmask;
    u32_t *dest_port;
    u32_t *src_port;
    int is_ingoing_packet; // whether it's an ingoing or outgoing packet
    int block; // whether we should block or unblock
    int protocol; // to which protocol this policy applies to
} firewall_policy_t;

#endif
