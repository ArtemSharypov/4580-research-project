#include <stdio.h>
#include <net/gen/in.h>

#include "policy_filter.h"

typedef struct policy_node {
    firewall_policy_t policy;
    struct policy_node *next_policy;
} policy_node_t;

policy_node_t *policies_head = NULL; // head of the list of the firewall policies

int total_num_policies = 0;

int add_policy(firewall_policy_t policy) 
{
    //todo implement 
    // add the policy to the end of the list or whatever.

    // malloc a new policy_node_t
    // then copy values over from this policy into that one
    
    if (policies_head == NULL) 
    {
        // set it to be head
    }
    else 
    {
        // otherwise traverse everything and add it to the end 
    }

    total_num_policies++;

    return 0;
}

int delete_policy(int policy_num)
{  
    if (policy_num <= total_num_policies)
    {
         // todo implement
        // simply remove the policy from list or whatever.
    }

    total_num_policies--;

    return 0;
}

int get_policies(policies_t *policies)
{
    policies->num_policies = 5;

    firewall_policy_t policy;

    policy.packet_type = 2;
    policy.action = 2;
    policy.protocol = 2;

    firewall_policy_t two;

    policy.packet_type = 3;
    policy.action = 3;
    policy.protocol = 3;

    // todo for these, it probably needs to have values set on the policies in the array
    // or malloced instead of this
    policies->policies[0] = policy;
    policies->policies[1] = two;

    // todo implement, needs to return a struct containing an array? of policies to user space somehow
    // let user space program print it all out and such



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