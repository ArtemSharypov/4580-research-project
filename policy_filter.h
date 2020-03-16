#ifndef POLICY_FILTER_H
#define POLICY_FILTER_H

// todo add parameters
int add_policy();

int delete_policy(int policy_num);

int print_all_policies();

// todo add parameters, these would be everything that identifies a packet such as the protocol
// and the different ip addresses and such
int should_block_packet();

#endif