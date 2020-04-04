#include <stdlib.h>
#include <net/gen/in.h>

#include "inet.h"
#include "buf.h"
#include "policy_filter.h"

typedef struct policy_node
{
    firewall_policy_t policy;
    struct policy_node *next_node;
} policy_node_t;

policy_node_t *policies_head = NULL; // head of the list of the firewall policies

int total_num_policies = 0; // Total number of policies that are part of the firewall

// Adds the policy to the end of the list of policies and increments the number
// of the total number of policies
// Returns 0
int add_policy(firewall_policy_t policy)
{
    policy_node_t *node = malloc(sizeof(policy_node_t));
    node->next_node = NULL;

    // Copy over the data from the passed in policy
    firewall_policy_t next_policy = node->policy;
    next_policy.src_ip_addr = policy.src_ip_addr;
    next_policy.src_netmask = policy.src_netmask;
    next_policy.dest_ip_addr = policy.dest_ip_addr;
    next_policy.dest_netmask = policy.dest_netmask;
    next_policy.dest_port = policy.dest_port;
    next_policy.src_port = policy.src_port;
    next_policy.packet_type = policy.packet_type;
    next_policy.action = policy.action;
    next_policy.protocol = policy.protocol;

    node->policy = next_policy;

    // If the head of the list of policies is NULL, set the node as the head
    // otherwise add it to the end of the list
    if (policies_head == NULL)
    {
        policies_head = node;
    }
    else
    {
        policy_node_t *curr_node = policies_head;

        while (curr_node->next_node != NULL)
        {
            curr_node = curr_node->next_node;
        }

        curr_node->next_node = node;
    }

    total_num_policies++;

    return 0;
}

// Deletes the policy that is at the policy_num position, if it exists
// On successful policy deletion it'll decrement the total_num_policies
// Returns 0
int delete_policy(int policy_num)
{
    if (policy_num <= total_num_policies)
    {
        // Delete the policy at the specified policy_num, if it is 1 then it'll delete the head of the list
        // otherwise it'll loop through the entire list of policies until the correct policy number is found
        if (policy_num == 1)
        {
            policy_node_t *next_node = policies_head->next_node;

            free(policies_head);

            policies_head = next_node;
        }
        else
        {
            policy_node_t *curr_node = policies_head;
            policy_node_t *prev_node = NULL;
            int node_num = 1;

            // Iterate through the list of policies until node_num is equal to policy_num
            while (curr_node->next_node != NULL && node_num < policy_num)
            {
                prev_node = curr_node;
                curr_node = curr_node->next_node;
                node_num++;
            }

            // Remove the node, update the pointer for the node before it, and free the memory
            prev_node->next_node = curr_node->next_node;
            free(curr_node);
        }

        total_num_policies--;
    }

    return 0;
}

// Retrieves the first MAX_NUM_POLICIES_TO_RETURN, or num_policies_to_return number of policies.
// The number is chosen based on which of the two numbers is smaller. Policies are returned by
// setting them into the "policies" parameter.
// Returns 0, and any firewall policies to return will be within the policies parameter.
int get_policies(policies_t *policies)
{
    int num_policies_to_return = MAX_NUM_POLICIES_TO_RETURN;

    // Only return MAX_NUM_POLICIES_TO_RETURN number of policies at most
    if (num_policies_to_return > total_num_policies)
    {
        num_policies_to_return = total_num_policies;
    }

    policies->num_policies = num_policies_to_return;

    int curr_policy_num = 0;
    policy_node_t *curr_node = policies_head;
    firewall_policy_t curr_policy;
    firewall_policy_t policy;

    // Go through the first num_policies_to_return policies and copy their data
    // into the policies to be returned.
    while (curr_node != NULL && curr_policy_num < num_policies_to_return)
    {
        curr_policy = curr_node->policy;
        policy = policies->policies[curr_policy_num];

        // Copy over the policy details
        policy.packet_type = curr_policy.packet_type;
        policy.action = curr_policy.action;
        policy.protocol = curr_policy.protocol;
        policy.src_ip_addr = curr_policy.src_ip_addr;
        policy.src_netmask = curr_policy.src_netmask;
        policy.dest_ip_addr = curr_policy.dest_ip_addr;
        policy.dest_netmask = curr_policy.dest_netmask;
        policy.dest_port = curr_policy.dest_port;
        policy.src_port = curr_policy.src_port;

        policies->policies[curr_policy_num] = policy;

        curr_node = curr_node->next_node;
        curr_policy_num++;
    }

    return 0;
}

// Used to check if the policy packet type and the type of the packet are different
// in terms of ingoing/outgoing type.
// Returns 0 if they're equal, and 1 if they're different
int has_diff_packet_type(int policy_packet_type, int packet_type)
{
    return policy_packet_type != packet_type;
}

// Used to check if the policy applies to a different protocol than the one of the packet
// If the policy applies to all protocols, it'll always return 0.
// Returns 0 if they're equal, and 1 if they're different
int has_diff_protocol(int policy_protocol, int packet_protocol)
{
    return policy_protocol != IPPROTO_ALL && policy_protocol != packet_protocol;
}

// Used to check if the policy and the packet have a different port.
// Can be used for destination, or source port.
// Returns 0 if they're equal or if the policy_port value is equal to VALUE_NOT_SET, and 1 if they're different
int has_diff_port(u16_t policy_port, u16_t packet_port)
{
    // Converts packet_port to host byte order before the comparison
    return policy_port != VALUE_NOT_SET && policy_port != ntohs(packet_port);
}

// Used to check if the policy and the packet have a different IP address.
// Can be used for the source, or destination IP address.
// If the policy IP address is set, and the policy_netmask is set then the netmask
// will be applied to the policy IP and the packet IP to check if they're different.
// Returns 0 if the IP addresses are the same when a netmask isn't set, if a netmask
// is set and IP addresses are the same with it applied, or if the IP address isn't set for
// the policy.
// Otherwise it will return 1, as in that they're different
int has_diff_ip_addr(u32_t policy_ip_addr, u32_t policy_netmask, u32_t packet_ip_addr)
{
    if (policy_ip_addr != VALUE_NOT_SET)
    {
        if (policy_netmask != VALUE_NOT_SET)
        {
            // Apply netmask to both ip addresses and return if they're equal or not
            return (policy_ip_addr & policy_netmask) != (packet_ip_addr & policy_netmask);
        }
        else
        {
            return policy_ip_addr != packet_ip_addr;
        }
    }

    return 0;
}

// Used to check if a packet should be blocked based on the policies within the firewall and the packet parameters passed in.
// It'll go through each policy and check if it should be applied. If a policy applies, it'll update the value of whether
// if a packet should be blocked or unblocked depending on the action stored for a policy.
// The last policy that applies to this packet will have its action applied to the packet, whether the packet should/shouldn't
// be blocked.
// Returns 1 if the packet should be blocked, or 0 if the packet should NOT be blocked.
int should_block_packet(int packet_type, u8_t protocol, u16_t src_port, u16_t dest_port, u32_t src_ip_addr, u32_t dest_ip_addr)
{
    policy_node_t *curr_node;
    firewall_policy_t policy;
    int block = 0;

    // Goes through each policy and checks if it applies to this packet
    // If it does, then it'll update the block value for whether this packet should, or shouldn't be blocked
    for (curr_node = policies_head; curr_node != NULL; curr_node = curr_node->next_node)
    {
        policy = curr_node->policy;
        
        // If the packet has any differing values compared to the policy, then the policy would not apply
        // therefore we can move onto the next policy
        if (has_diff_packet_type(policy.packet_type, packet_type) ||
            has_diff_protocol(policy.protocol, protocol) ||
            has_diff_port(policy.src_port, src_port) ||
            has_diff_port(policy.dest_port, dest_port) ||
            has_diff_ip_addr(policy.src_ip_addr, policy.src_netmask, src_ip_addr) ||
            has_diff_ip_addr(policy.dest_ip_addr, policy.dest_netmask, dest_ip_addr))
        {
            continue;
        }

        block = policy.action == BLOCK;
    }

    return block;
}

// Used to check if a packet should be blocked based on the policies within the firewall and the packet parameters passed in.
// Returns 1 if the packet should be blocked, or 0 if the packet should NOT be blocked.
int should_block_ingoing_packet(u8_t protocol, u16_t src_port, u16_t dest_port, u32_t src_ip_addr, u32_t dest_ip_addr)
{
    return should_block_packet(INGOING_PACKET, protocol, src_port, dest_port, src_ip_addr, dest_ip_addr);
}

// Used to check if a packet should be blocked based on the policies within the firewall and the packet parameters passed in.
// Returns 1 if the packet should be blocked, or 0 if the packet should NOT be blocked.
int should_block_outgoing_packet(u8_t protocol, u16_t src_port, u16_t dest_port, u32_t src_ip_addr, u32_t dest_ip_addr)
{
    return should_block_packet(OUTGOING_PACKET, protocol, src_port, dest_port, src_ip_addr, dest_ip_addr);
}