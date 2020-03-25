
#ifndef FIREWALL_DEF_H
#define FIREWALL_DEF_H

#include <sys/types.h>

// Used to indicate that the policy applies to all protocols
#define IPPROTO_ALL 0

// Packet type, whether a packet is ingoing or outgoing
#define OUTGOING_PACKET 1
#define INGOING_PACKET 2

// Packet Action, if a packet should be blocked or unblocked
#define BLOCK 1
#define UNBLOCK 2

// Default value, indicates that the specified variable of the policy was not set
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
    int num_policies; // Number of policies that are contained within the policies array
} policies_t;

#endif
