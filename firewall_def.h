
#ifndef FIREWALL_DEF_H
#define FIREWALL_DEF_H

#include <sys/types.h>

#define ALL 0

#define OUTGOING_PACKET 1
#define INGOING_PACKET 2

#define BLOCK 1
#define UNBLOCK 0

#define VALUE_NOT_SET 0

// Max number of policies that can be returned within policies_t due to the size restrictions
#define MAX_NUM_POLICIES_TO_RETURN 10

typedef struct firewall_policy 
{
    u32_t src_ip_addr;
    u32_t src_netmask;
    u32_t dest_ip_addr;
    u32_t dest_netmask;
    int dest_port;
    int src_port;
    int packet_type; // whether it's an ingoing or outgoing packet
    int action; // whether we should block or unblock
    int protocol; // to which protocol this policy applies to
} firewall_policy_t;

typedef struct policies
{
    firewall_policy_t policies[MAX_NUM_POLICIES_TO_RETURN];
    int num_policies;
} policies_t;

#endif
