#include <sys/types.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netinet/in.h>
#include <net/gen/firewall_def.h>
#include <net/hton.h>
#include <net/netlib.h>
#include <netdb.h>
#include <net/gen/in.h>
#include <net/gen/inet.h>
#include <net/gen/ip_io.h>

// Definitions for the available commands
#define ADD_IN_POLICY "--in" // Add policy to ingoing packets
#define ADD_OUT_POLICY "--out" // Add policy to outgoing packets
#define DELETE_POLICY "--delete" // Delete a policy
#define PRINT_POLICIES "--print" // Print the policies

// Position of where the command must be within arguments, for adding / deleting / printing policies
#define ARGS_EXPECTED_COMMAND_POS 1 

#define MIN_NUMBER_ARGS 2 // Minimum number of expected arguments for any command 
#define NUM_ARGS_DELETE_COMMAND 3 // Number of expected arguments for a delete a policy 
#define NUM_ARGS_PRINT_COMMAND 2 // Number of expected arguments for printing policies
#define MIN_NUM_ARGS_ADD_COMMAND 6 // Minimum number of expected arguments for adding a new policy

// Definitions for the values that indicate a criteria when parsing input to add a new policy 
#define PROTO "--proto" // Indicates the next value is for the protocol
#define ACTION "--action" // Indicates the next value is for the action 
#define SRC_IP "--srcip" // Indicates the next value is for the source IP address
#define SRC_NETMASK "--srcnetmask"  // Indicates the next value is for the source netmask
#define SRC_PORT "--srcport" // Indicates the next value is for the source port
#define DEST_IP "--destip" // Indicates the next value is for the destination IP address
#define DEST_NETMASK "--destnetmask" // Indicates the next value is for the destination netmask
#define DEST_PORT "--destport" // Indicates the next value is for the destination port

// Definitions for the strings that define a protocol, or type of action for a policy
#define PROTO_ALL "ALL" // Policy applies to ALL protocols
#define PROTO_TCP "TCP" // Policy applies to TCP only
#define PROTO_UDP "UDP" // Policy applies to UDP only
#define PROTO_ICMP "ICMP" // Policy applies to ICMP only
#define ACTION_BLOCK "BLOCK" // Block packet action
#define ACTION_UNBLOCK "UNBLOCK" // Unblock packet action

// Helper function for getting the ip file descriptor.
// Returns the file descriptor as an int.
int get_ip_fd()
{
    int ip_fd;
    char *ip_device = ip_device= getenv("IP_DEVICE");
    
    if (!ip_device)
    {
        ip_device = IP_DEVICE;
    }

    ip_fd = open(ip_device, O_RDWR);

	if (ip_fd == -1)
	{
		fprintf(stderr, "minifirewall: unable to open('%s'): %s\n", ip_device, strerror(errno));
		exit(1);
	}

    return ip_fd;
}

// TODO add comments
void usage()
{
    // TODO
    printf("This should be used as \n");
}

// Handles deleting a specified policy that is represented by a number within the args array.
// It'll verify that there is a correct number of args passed in, and that the last argument
// is a positive number representing the policy that should be deleted.
// If the number is valid, then it'll do an ioctl call to delete the policy.
// Otherwise if there is to many or to few arguments, or a negative / zero policy number it'll print
// the usage expectations for the program to the console.
void handle_delete_command(int num_args, char *args[], int ip_fd)
{
    // Number of arguments has to be equal to the number expected for a delete policy input
    // If the value is different, then print the usage expectations for the program 
    if (num_args != NUM_ARGS_DELETE_COMMAND)
    {
        usage();
        return;
    }

    // Parse the last argument passed in as a number
    int policy_num_to_delete = atoi(args[NUM_ARGS_DELETE_COMMAND - 1]);

    // TODO delete once tested
    printf("For test purposes: Deleting policy number %d \n", policy_num_to_delete);

    // Policy number to delete has to be a positive, non zero number
    if (policy_num_to_delete < 1)
    {
        usage();
        return;
    }

    // Call to delete the firewall policy using the parsed value
    int result = ioctl(ip_fd, FIREWALLPOLICYREMOVE, &policy_num_to_delete);

    if (result == -1 ) 
    { 
        printf("failed ioctl call \n");
    }
}

// Handles printing the current policies from the firewall.
// It'll do an ioctl call to grab the firewall policies, and then print out the details of each policy.
// It'll print any values set for each policy, if an optional field for a policy is not set then
// the value will NOT be printed.
void handle_print_command(int num_args, char *args[], int ip_fd)
{
    // Number of arguments has to be equal to the number expected for the print command
    // If the value is different, then print the usage expectations for the program 
    if (num_args != NUM_ARGS_PRINT_COMMAND)
    {
        usage();
        return;
    }

    policies_t policies;

    // Call to get the current firewall policies
    int result = ioctl(ip_fd, FIREWALLPOLICYPRINT, &policies);

    if (result == -1 )
    { 
        printf("failed ioctl call \n");
        return;
    }

    if (policies.num_policies == 0)
    {
        printf("Firewall currently has no policies configured \n");
    }

    int i;
    firewall_policy_t curr_policy;
    char ip_addr[INET_ADDRSTRLEN]; 
    char netmask[INET_ADDRSTRLEN];

    // Go through each policy and print them. Each line is a separate policy. 
    // If a optional policy field is not set it will not be printed.
    for (i = 0; i < policies.num_policies; i++) 
    {
        curr_policy = policies.policies[i];

        // Current Policy number
        printf("Policy #%d | ", (i+1));

        // Packets that this policy applies to, either ingoing or outgoing
        if (curr_policy.packet_type == INGOING_PACKET)
        {
            printf("INGOING PACKETS | ");
        }
        else if (curr_policy.packet_type == OUTGOING_PACKET)
        {
            printf("OUTGOING PACKETS | ");
        }

        // Whether packets should be blocked, or unblocked
        if (curr_policy.action == BLOCK)
        {
            printf("BLOCK | ");
        }
        else if (curr_policy.action == UNBLOCK)
        {
            printf("UNBLOCK | ");
        }

        // Protocol that this policy applies to
        if (curr_policy.protocol == IPPROTO_ALL)
        {
            printf("ALL Protocols | ");
        } 
        else if (curr_policy.protocol == IPPROTO_ICMP)
        {
            printf("ICMP Protocol | ");
        } 
        else if (curr_policy.protocol == IPPROTO_TCP)
        {
            printf("TCP Protocol | ");
        }
        else if (curr_policy.protocol == IPPROTO_UDP)
        {
            printf("UDP Protocol | ");
        }

        // Source IP address the policy applies to
        if (curr_policy.src_ip_addr != VALUE_NOT_SET)
        {
            // Convert the source IP address from binary form to text form
            if (inet_ntop(AF_INET, &(curr_policy.src_ip_addr), ip_addr, INET_ADDRSTRLEN) != NULL)
            {
                printf(" Src IP Addr %s | ", ip_addr);
            }
        }

        // Source Netmask that would be applied to the source IP address
        if (curr_policy.src_netmask != VALUE_NOT_SET)
        {
            // Convert the source netmask from binary form to text form
            if (inet_ntop(AF_INET, &(curr_policy.src_netmask), netmask, INET_ADDRSTRLEN) != NULL)
            {
                printf(" Src Netmask %s | ", netmask);
            }
        }

        // Print source port if the value is set
        if (curr_policy.src_port != VALUE_NOT_SET)
        {
            printf(" Src Port %d | ", curr_policy.src_port);
        }

        // Destination IP address the policy applies to
        if (curr_policy.dest_ip_addr != VALUE_NOT_SET)
        {
            // Convert the destination IP address from binary form to text form
            if (inet_ntop(AF_INET, &(curr_policy.dest_ip_addr), ip_addr, INET_ADDRSTRLEN) != NULL)
            {
                printf(" Dest IP Addr %s | ", ip_addr);
            }
        }

        // Destination Netmask that would be applied to the destination IP address
        if (curr_policy.dest_netmask != VALUE_NOT_SET)
        {
            // Convert the destination netmask from binary form to text form
            if (inet_ntop(AF_INET, &(curr_policy.dest_netmask), netmask, INET_ADDRSTRLEN) != NULL)
            {
                printf(" Dest Netmask %s | ", netmask);
            }
        }

        // Print destination port if the value is set
        if (curr_policy.dest_port != VALUE_NOT_SET)
        {
            printf(" Dest Port %d | ", curr_policy.dest_port);
        }

        printf("\n");
    }
}

// Helper function for parsing the protocol value from protocol_input parameter
// If it is one of ALL, TCP, UDP, or ICMP protocol it'll set it on the policy
// Otherwise it'll do nothing
// Returns 1 if there was a valid protocol, or 0 if there was not.
int parse_protocol(char *protocol_input, firewall_policy_t *policy)
{
    int set_protocol = 1;

    // Check and set which protocol the policy should apply to
    if (strcmp(protocol_input, PROTO_ALL) == 0)
    {
        policy->protocol = IPPROTO_ALL;
    }
    else if (strcmp(protocol_input, PROTO_TCP) == 0)
    {
        policy->protocol = IPPROTO_TCP; 
    }
    else if (strcmp(protocol_input, PROTO_UDP) == 0)
    {
        policy->protocol = IPPROTO_UDP;
    }
    else if (strcmp(protocol_input, PROTO_ICMP) == 0)
    {   
        policy->protocol = IPPROTO_ICMP;
    }
    else 
    {
        set_protocol = 0;
    }

    return set_protocol;
}

// Helper function for parsing the action value from action_input parameter
// If it is one of UNBLOCK or BLOCK strings it'll set it on the policy
// Otherwise it'll do nothing
// Returns 1 if there was a valid action, or 0 if there was not.
int parse_action(char *action_input, firewall_policy_t *policy)
{
    int set_action = 1;

    // Check and set the action that should be used for the policy
    if (strcmp(action_input, ACTION_BLOCK) == 0)
    {
        policy->action = BLOCK;
    }
    else if (strcmp(action_input, ACTION_UNBLOCK) == 0)
    {
        policy->action = UNBLOCK;
    }
    else 
    {
        set_action = 0;
    }

    return set_action;
}

// TODO document
void handle_add_command(int num_args, char *args[], int packet_type, int ip_fd)
{
    // TODO remove
    // policy is for in or outgoing packets
    printf ("out/ingoing packet applied to policy \n");

    // Number of args has to be an even number as each criteria will have a value associated with it
    // And there has to enough args to cover the expected values from protocol, action, and in/outgoing packet type
    if (num_args % 2 != 0 || num_args < MIN_NUM_ARGS_ADD_COMMAND)
    {
        usage();
        return;
    }

    firewall_policy_t policy;

    policy.protocol = VALUE_NOT_SET;
    policy.src_ip_addr = VALUE_NOT_SET;
    policy.src_netmask = VALUE_NOT_SET;
    policy.dest_ip_addr = VALUE_NOT_SET;
    policy.dest_netmask = VALUE_NOT_SET;
    policy.dest_port = VALUE_NOT_SET;
    policy.src_port = VALUE_NOT_SET;
    policy.action = VALUE_NOT_SET;
    
    policy.packet_type = packet_type;

    // Tracking for if optional values were set or not, including that if a protocol was set as it's mandatory
    int protocol_set = 0;
    int src_ip_set = 0;
    int src_netmask_set = 0;
    int src_port_set = 0;
    int dest_ip_set = 0;
    int dest_netmask_set = 0;
    int dest_port_set = 0;

    // Position within args that indicate a criteria to be added to the policy
    int criteria_pos = ARGS_EXPECTED_COMMAND_POS + 1;
    
    // Position within args that indicate the value of a criteria to be set for the policy
    int value_pos = criteria_pos + 1;

    // TODO comment, also maybe split the logic into small functions for each type? returns 1 on success, 0 on failure or something
    while (criteria_pos < num_args && value_pos < num_args)
    {
        if (strcmp(args[criteria_pos], PROTO) == 0) 
        {
            // Protocol was already set, therefore invalid input
            // Print usage and don't add the policy
            if (protocol_set)
            {
                usage();
                return;
            }
            
            // Parses the protocol contained at value_pos, and updates that the protocol was set
            // If it fails, then it'll print usage and skip adding the policy
            if (parse_protocol(args[value_pos], &policy))
            {
                protocol_set = 1;
            }
            else 
            {
                usage();
                return;
            }
        } 
        else if (strcmp(args[criteria_pos], ACTION) == 0) 
        {
            // Action was already set, therefore invalid input
            // Print usage and don't add the policy
            if (policy.action != VALUE_NOT_SET)
            {
                usage();
                return;
            }   

            // If parsing the action fails then print usage and skip adding the policy
            if (!parse_action(args[value_pos], &policy))
            {
                usage();
                return;
            }
        } 
        else if (strcmp(args[criteria_pos], SRC_IP) == 0) 
        {
            // Source IP was already set, therefore invalid input
            // Print usage and don't add the policy
            if (src_ip_set)
            {
                usage();
                return;
            }  

            // todo will need IP address format to be converted to bits. function call is inet_pton
            // todo add logic
        }
        else if (strcmp(args[criteria_pos], SRC_NETMASK) == 0) 
        {
            // Source netmask was already set, therefore invalid input
            // Print usage and don't add the policy
            if (src_netmask_set)
            {
                usage();
                return;
            }  

             // todo will need IP address format to be converted to bits. function call is inet_pton
            // todo add logic
        }
        else if (strcmp(args[criteria_pos], SRC_PORT) == 0) 
        {
            // Source port was already set, therefore invalid input
            // Print usage and don't add the policy
            if (src_port_set)
            {
                usage();
                return;
            }  

            // todo add logic
        }
        else if (strcmp(args[criteria_pos], DEST_IP) == 0) 
        {
            // Destination IP was already set, therefore invalid input
            // Print usage and don't add the policy
            if (dest_ip_set)
            {
                usage();
                return;
            }  

             // todo will need IP address format to be converted to bits. function call is inet_pton
            // todo add logic
        }
        else if (strcmp(args[criteria_pos], DEST_NETMASK) == 0) 
        {
            // Destination netmask was already set, therefore invalid input
            // Print usage and don't add the policy
            if (dest_netmask_set)
            {
                usage();
                return;
            }  

             // todo will need IP address format to be converted to bits. function call is inet_pton
            // todo add logic
        }
        else if (strcmp(args[criteria_pos], DEST_PORT) == 0) 
        {
            // Destination port was already set, therefore invalid input
            // Print usage and don't add the policy
            if (dest_port_set)
            {
                usage();
                return;
            }  

            // todo add logic
        }
        else 
        {
            usage();
            return;
        }

        // Increment by 2 since we parse 2 positions at a time, one for the criteria type and the other for the value
        criteria_pos += 2;
        value_pos += 2;
    }

    // TODO clean this logic up slightly, mainly for the port stuff
    // If the protocol wasn't set, action wasn't set, or if a netmask was set without the corresponding ip address for src/dest
    // then don't add the policy and print the usage expectations
    if (!protocol_set ||
        (src_netmask_set && !src_ip_set) ||
        (dest_netmask_set && !dest_ip_set) ||
        ((policy.protocol == IPPROTO_ALL || policy.protocol == IPPROTO_ICMP) && (src_port_set || dest_port_set)) ||
        policy.action == VALUE_NOT_SET)
    {
        usage();
        return;
    }

    int result = ioctl(ip_fd, FIREWALLPOLICYADD, &policy);

    if (result == -1 )
    { 
        printf("failed ioctl call \n");
    }
}

// Checks the passed in args for if there is a valid command to be executed
// If so, it'll call the appropriate function to handle it
// Otherwise it'll print the expected usage for the program
void check_args_for_command(int num_args, char *args[])
{
    int ip_fd = get_ip_fd();

    // Check the command that was passed in the args
    // If there was a command, call the appropriate function to handle it, otherwise
    // print the expected usage for this program
    if (strcmp(args[ARGS_EXPECTED_COMMAND_POS], ADD_IN_POLICY) == 0) 
    {
        handle_add_command(num_args, args, INGOING_PACKET, ip_fd);
    } 
    else if (strcmp(args[ARGS_EXPECTED_COMMAND_POS], ADD_OUT_POLICY) == 0) 
    {
        handle_add_command(num_args, args, OUTGOING_PACKET, ip_fd);
    }
    else if (strcmp(args[ARGS_EXPECTED_COMMAND_POS], DELETE_POLICY) == 0) 
    {
        handle_delete_command(num_args, args, ip_fd);
    } 
    else if(strcmp(args[ARGS_EXPECTED_COMMAND_POS], PRINT_POLICIES) == 0) 
    {
        handle_print_command(num_args, args, ip_fd);
    } 
    else 
    {
        usage();
    }
}

int main(int argc, char *argv[])
{
    if (argc < MIN_NUMBER_ARGS) 
    {
        usage();   
        exit(1);
    }

    check_args_for_command(argc, argv);

    return(0);
}