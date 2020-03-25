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

#define ADD_IN_POLICY "--in" // Add policy to ingoing packets
#define ADD_OUT_POLICY "--out" // Add policy to outgoing packets
#define DELETE_POLICY "--delete" // Delete a policy
#define PRINT_POLICIES "--print" // Print the policies
#define ACTION_BLOCK "BLOCK" // Block packet action
#define ACTION_UNBLOCK "UNBLOCK" // Unblock packet action

// Position of where the command must be within arguments, for adding / deleting / printing policies
#define ARGS_EXPECTED_COMMAND_POS 1 

#define MIN_NUMBER_ARGS 2 // Minimum number of expected arguments for any command 
#define NUM_ARGS_DELETE_COMMAND 3 // Number of expected arguments for a delete a policy 
#define NUM_ARGS_PRINT_COMMAND 2 // Number of expected arguments for printing policies
#define MIN_NUM_ARGS_ADD_COMMAND 6 // Minimum number of expected arguments for adding a new policy

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

    int i;
    firewall_policy_t curr_policy;
    char ip_addr[INET_ADDRSTRLEN];
    char netmask[INET_ADDRSTRLEN];

    if (policies.num_policies == 0)
    {
        printf("Firewall currently has no policies configured \n");
    }

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

// TODO document
void handle_add_command(int num_args, char *args[], int packet_type, int ip_fd)
{
    // policy is for in or outgoing packets
    printf ("out/ingoing packet applied to policy \n");

    firewall_policy_t policy;

    policy.action = BLOCK;

    // protocols are defined as the following (which come from IP side)
    // IPPROTO_ICMP 1
    // IPPROTO_TCP 6
    // IPPROTO_UDP 17
    // and for ALL use IPPROTO_ALL

    // testing purposes
    policy.protocol = IPPROTO_ICMP;

    policy.src_ip_addr = 0;
    policy.src_netmask = 0;
    policy.dest_ip_addr = 0;
    policy.dest_netmask = 0;
    policy.dest_port = 0;
    policy.src_port = 0;
    

    policy.packet_type = packet_type;

    // todo will need IP address format to be converted to bits? see: add_route.c

    int result = ioctl(ip_fd, FIREWALLPOLICYADD, &policy);

    if (result == -1 )
    { 
        printf("failed ioctl call \n");
    }
    // todo everything else
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