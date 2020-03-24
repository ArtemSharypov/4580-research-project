#ifndef POLICY_FILTER_H
#define POLICY_FILTER_H

#include <net/gen/firewall_def.h>

// Adds the policy to the end of the list of policies and increments the number
// of the total number of policies
// Returns 0
int add_policy(firewall_policy_t policy);

// Deletes the policy that is at the policy_num position, if it exists
// On successful policy deletion it'll decrement the total_num_policies
// Returns 0
int delete_policy(int policy_num);

// Retrieves the first MAX_NUM_POLICIES_TO_RETURN, or num_policies_to_return number of policies.
// The number is chosen based on which of the two numbers is smaller. Policies are returned by 
// setting them into the "policies" parameter.
// Returns 0, and any firewall policies to return will be within the policies parameter.
int get_policies(policies_t *policies);

// Used to check if a packet should be blocked based on the policies within the firewall and the packet parameters passed in.
// Returns 1 if the packet should be blocked, or 0 if the packet should NOT be blocked.
int should_block_ingoing_packet(int protocol, int src_port, int dest_port, u32_t src_ip_addr, u32_t dest_ip_addr);

// Used to check if a packet should be blocked based on the policies within the firewall and the packet parameters passed in.
// Returns 1 if the packet should be blocked, or 0 if the packet should NOT be blocked.
int should_block_outgoing_packet(int protocol, int src_port, int dest_port, u32_t src_ip_addr, u32_t dest_ip_addr;

#endif