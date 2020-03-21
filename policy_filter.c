#include <stdio.h>
#include <stdlib.h>
#include <net/gen/in.h>

#include "policy_filter.h"

typedef struct policy_node {
    firewall_policy_t policy;
    struct policy_node *next_node;
} policy_node_t;

policy_node_t *policies_head = NULL; // head of the list of the firewall policies

int total_num_policies = 0;

int add_policy(firewall_policy_t policy) 
{
    policy_node_t *node = malloc(sizeof(policy_node_t));
    node->next_node = NULL;

    // copy over the data from the policy
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
    
    if (policies_head == NULL) 
    {
        policies_head = node;
    }
    else 
    {   
        // Add the policy to the end of the list
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

int delete_policy(int policy_num)
{  
    if (policy_num <= total_num_policies)
    {
        // Delete the policy at the specified policy_num
        if (policy_num == 1) 
        {
            // if policy_num is 1, then thats the first entry in the list which will be the head of the list
            policy_node_t *next_node = policies_head->next_node;

            free(policies_head);

            policies_head = next_node;
        }
        else
        {
            policy_node_t *curr_node = policies_head;
            policy_node_t *prev_node = NULL;
            int node_num = 1;

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

int has_diff_packet_type(int policy_packet_type, int packet_type) 
{
    return policy_packet_type != packet_type;
}

int has_diff_protocol(int policy_protocol, int packet_protocol)
{
    return policy_protocol != ALL && policy_protocol != packet_protocol;
}

// Can be source or destination port
int has_diff_port(int policy_port, int packet_port)
{
    return policy_port != VALUE_NOT_SET && policy_port != packet_port;
}

// Can be source or destination IP address & netmask
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

// returns 0 if false, 1 otherwise 
int should_block_packet(int packet_type, int protocol, int src_port, int dest_port, u32_t src_ip_addr, u32_t dest_ip_addr)
{
    // protocols are defined as the following (which come from IP side)
    // IPPROTO_ICMP 1
    // IPPROTO_TCP 6
    // IPPROTO_UDP 17

    policy_node_t *curr_node;
    firewall_policy_t policy;
    int block = 0;

    // go through every policy and compare them
    // todo comment this better
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

        block = policy.action;
    }

    return block;
}

// returns 0 if false, 1 otherwise 
int should_block_ingoing_packet(int protocol, int src_port, int dest_port, u32_t src_ip_addr, u32_t dest_ip_addr) 
{
    return should_block_packet(INGOING_PACKET, protocol, src_port, dest_port, src_ip_addr, dest_ip_addr);
}

// returns 0 if false, 1 otherwise 
int should_block_outgoing_packet(int protocol, int src_port, int dest_port, u32_t src_ip_addr, u32_t dest_ip_addr)
{
    return should_block_packet(OUTGOING_PACKET, protocol, src_port, dest_port, src_ip_addr, dest_ip_addr);
}