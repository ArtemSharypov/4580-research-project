#ifndef POLICY_FILTER_H
#define POLICY_FILTER_H

#include <net/gen/firewall_def.h>

int add_policy(firewall_policy_t policy);

int delete_policy(int policy_num);

int get_policies(policies_t *policies);

// todo add parameters, these would be everything that identifies a packet such as the protocol
// and the different ip addresses and such
int should_block_ingoing_packet();

// todo add parameters, these would be everything that identifies a packet such as the protocol
// and the different ip addresses and such
int should_block_outgoing_packet();

#endif