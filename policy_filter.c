#include <stdio.h>
#include <net/gen/in.h>

#include "policy_filter.h"


// todo this will be the thing that contains functions for adding to, deleting from, printing the policies and 
// for checking if a packet should be filtered

// todo define the struct for storing a policy
// todo define the node struct for storing a list of policies

// todo define a head for the list of policies

int totalNumPolicies = 0;

// todo add parameters (copy from header)
int add_policy(firewall_policy_t policy) 
{
    //todo implement 
    // add the policy to the end of the list or whatever.

    totalNumPolicies++;

    return 0;
}

int delete_policy(int policy_num)
{  
    // todo implement
    // simply remove the policy from list or whatever.

    totalNumPolicies--;

    return 0;
}

int print_all_policies()
{
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

    return totalNumPolicies > 0;
}

int should_block_ingoing_packet() 
{
    return should_block_packet(1);
}

int should_block_outgoing_packet()
{
    return should_block_packet(0);
}