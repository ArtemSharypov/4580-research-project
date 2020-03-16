#include <stdio.h>

#include "policy_filter.h"

// todo this will be the thing that contains functions for adding to, deleting from, printing the policies and 
// for checking if a packet should be filtered

// todo define the struct for storing a policy
// todo define the node struct for storing a list of policies

// todo define a head for the list of policies

// todo add parameters (copy from header)
int add_policy(firewall_policy_t policy) 
{
    //todo implement

    return 0;
}

int delete_policy(int policy_num)
{  
    // todo implement

    return 0;
}

int print_all_policies()
{
    // todo implement, needs to return a string to user space somehow
    // including a descriptive title above, and the number that represents that policy
    return 0;
}

// todo add parameters, these would be everything that identifies a packet such as the protocol
// and the different ip addresses and such
// copy from the header
// returns 0 if false, 1 otherwise 
int should_block_packet()
{
    // todo implement

    return 0;
}