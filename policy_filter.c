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

// todo add parameters, these would be everything that identifies a packet such as the protocol
// and the different ip addresses and such
// copy from the header
// returns 0 if false, 1 otherwise 
int should_block_packet(int is_ingoing_packet)
{
    // todo implement

    // protocols are defined as the following (which come from IP side)
    // IPPROTO_ICMP 1
    // IPPROTO_TCP 6
    // IPPROTO_UDP 17

    // go through each policy and compare them, maybe use small helper function to make it easier to understand
    // the newest policy (the one at the end of the list) would be the one that decides if something is blocked or not
    // ie if there is an unblock for a type at the end of the list after a block, then we won't block the packet

    int stuff = IPPROTO_ICMP;

    return total_num_policies > 0;
}

// todo add parameters, these would be everything that identifies a packet such as the protocol
// and the different ip addresses and such
// copy from the header
// returns 0 if false, 1 otherwise 
int should_block_ingoing_packet() 
{
    return should_block_packet(1);
}

// todo add parameters, these would be everything that identifies a packet such as the protocol
// and the different ip addresses and such
// copy from the header
// returns 0 if false, 1 otherwise 
int should_block_outgoing_packet()
{
    return should_block_packet(0);
}