/*
 minifirewall.c 
 COMP 4580 WInter 2020
 University Of Manitoba
 Property of Artem Sharypov & Adam Salsi
 April 6th, 2020
*/

// Basic c libraries
#include <sys/types.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

// Inet libraries
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
#define TEST_POLICIES  "--test" // Test all policies
// TODO: For future add a debug command, we tried adding one but had too many bugs ironically enough 

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

// Paths of test content
#define TEST_PATH_INPUT "../usr/src/minix/commands/minifirewall/testResults/testOutputIn.txt"
#define TEST_PATH_OUTPUT "../usr/src/minix/commands/minifirewall/testResults/testOutputOut.txt"

// Logging file Ptr
FILE *logPtr = NULL;

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
} // End get_ip_fd

/*
 Prints the usage expectation for this program. 
 It includes the commands that can be used and the arguments that each command requires, including optional
 values for adding a new policy. 
 Future Consideration: Could abstract into a help command --help, and leave only the first important lines in usage
*/
void usage()
{
    if (logPtr != NULL)
    {
      fprintf(logPtr, "\nUsage method called\n"); 
    }
    
    printf("This program/command can be used in the following ways\n");
    printf("\n");
    printf("Add a policy to the firewall: \n");
    printf("Usage: minifirewall --in --action action --proto protocol [--srcip srcip] [--srcnetmask srcnetmask]\n");
    printf("[--srcport srcport] [--destip destip] [--destnetmask destnetmask] [--destport destport] \n");
    printf("\n");
    printf("Usage: minifirewall --out --action action --proto protocol [--srcip srcip] [--srcnetmask srcnetmask] \n");
    printf("[--srcport srcport] [--destip destip] [--destnetmask destnetmask] [--destport destport] \n");
    printf("\n");
    printf("\t Anything in [] is an optional criteria for the policy.\n");
    printf("\t action, proto, in/out, and any set optional criterias must match a packets for the policy to apply.\n");
    printf("\t --out applies to outgoing packets, --in applies to incoming packets.\n");
    printf("\t action must be one of BLOCK, or UNBLOCK to block/unblock a packet based on the policy criteria.\n");
    printf("\t protocol must be one of TCP, UDP, ICMP, or ALL for which protocol the policy applies to.\n");
    printf("\t srcip, srcnetmask, destip, destnetmask must be in IPV4 decimal & dot format.\n");
    printf("\t srcport, and destport must be a positive value, and protocol must be UDP or TCP.\n");
    printf("\n");
    printf("Delete a policy from the firewall: \n");
    printf("Usage: minifirewall --delete policynum\n");
    printf("\n");
    printf("\t policynum must be a positive value, indicating which policy should be deleted. \n");
    printf("\n");
    printf("Print all policies in the firewall: \n");
    printf("Usage: minifirewall --print \n");
    printf("\n");
    printf("Test the functionality of the firewall: \n");
    printf("Usage: minifirewall --test");
    printf("\n");
} // End usage

// Helper function for calling usage(), and exiting the program in times where there is invalid
// input and the program won't continue running. 
void invalid_input()
{
    if (logPtr != NULL)
    {
      fprintf(logPtr, "\nUser entered invalid command, sending usage list...\n"); 
    }
    usage();
    exit(1);
} // End invalid_input

// This function is responsible for calling the test script of our firewall
void handle_test_command(int num_args, char *args[], int ip_fd)
{
   if (logPtr != NULL)
   {
      fprintf(logPtr, "\nInvoking test suite\n"); 
   }
    
   // Run the test suite
   system(" bash ./firewallTestIn.sh");
   system(" bash ./firewallTestOut.sh");
} // End handle_test_command

/* 
 Enable command logging
 This function can be abstracted into a --debug command fairly easily, we opted to leave it as mandatory for    testing and design purposes 
*/
void initLogging()
{
  logPtr = fopen("testResults/firewallLogs.txt", "a+");
  if(logPtr == NULL) 
  {
   printf("\nCould not open or find the log file for minifirewall. \n"); 
   exit(1); 
  }
  else
  {
   struct tm tm = *localtime(&(time_t){time(NULL)}); 
   fprintf(logPtr, "-------------------------------------------\n");
   fprintf(logPtr, "Timestamp: %s", asctime(&tm));
   fprintf(logPtr, "Logging Function calls for minifirewall..."); 
  }
} // End initLogging

/* 
 Handles deleting a specified policy that is represented by a number within the args array.
 It'll verify that there is a correct number of args passed in, and that the last argument
 is a positive number representing the policy that should be deleted.
 If the number is valid, then it'll do an ioctl call to delete the policy.
 Otherwise if there is to many or to few arguments, or a negative / zero policy number it'll print
 the usage expectations for the program to the console.
 */
void handle_delete_command(int num_args, char *args[], int ip_fd)
{
    // Number of arguments has to be equal to the number expected for a delete policy input
    // If the value is different, then print the usage expectations for the program 
    if (num_args != NUM_ARGS_DELETE_COMMAND)
    {
        invalid_input();
    }
    
    if (logPtr != NULL)
    {
      fprintf(logPtr, "\nInvoking Deletion Function\n"); 
    }

    // Parse the last argument passed in as a number
    int policy_num_to_delete = atoi(args[NUM_ARGS_DELETE_COMMAND - 1]);

    printf("Deleting policy number %d \n", policy_num_to_delete);
    if (logPtr != NULL) 
    {
      fprintf(logPtr, "\nDeleting policy number %d \n", policy_num_to_delete);
    }

    // Policy number to delete has to be a positive, non zero number
    if (policy_num_to_delete < 1)
    {
        invalid_input();
    }

    // Call to delete the firewall policy using the parsed value
    int result = ioctl(ip_fd, FIREWALLPOLICYREMOVE, &policy_num_to_delete);

    if (result == -1 ) 
    { 
        printf("failed ioctl call \n");
        if (logPtr != NULL) 
        {
          fprintf(logPtr, "\nfailed ioctl call \n");
        }
    }
} // End handle_delete_command

/* 
 Handles printing the current policies from the firewall.
 It'll do an ioctl call to grab the firewall policies, and then print out the details of each policy.
 It'll print any values set for each policy, if an optional field for a policy is not set then
 the value will NOT be printed.
*/
void handle_print_command(int num_args, char *args[], int ip_fd)
{
    // Number of arguments has to be equal to the number expected for the print command
    // If the value is different, then print the usage expectations for the program 
    if (num_args != NUM_ARGS_PRINT_COMMAND)
    {
        invalid_input();
    }
    
    if (logPtr != NULL)
    {
      fprintf(logPtr, "\nPrinting Policies\n"); 
      if (logPtr != NULL) 
      {
        fprintf(logPtr, "\nPrinting Policies\n");
      }
    }

    policies_t policies;

    // Call to get the current firewall policies
    int result = ioctl(ip_fd, FIREWALLPOLICYPRINT, &policies);

    if (result == -1 )
    { 
        printf("failed ioctl call \n");
        if (logPtr != NULL) 
        {
          fprintf(logPtr, "\nfailed ioctl call \n");
        }
        return;
    }

    if (policies.num_policies == 0)
    {
        printf("Firewall currently has no policies configured \n");
        if (logPtr != NULL) 
        {
          fprintf(logPtr, "\nFirewall currently has no policies configured \n");
        }
    }

    int i;
    firewall_policy_t curr_policy;

    // Go through each policy and print them. Each line is a separate policy. 
    // If a optional policy field is not set it will not be printed.
    for (i = 0; i < policies.num_policies; i++) 
    {
        curr_policy = policies.policies[i];

        // Current Policy number
        printf("Policy #%d | ", (i+1));
        if (logPtr != NULL) 
        {
          fprintf(logPtr, "\nPolicy #%d \n", (i+1));
        }

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
            printf("Src IP Addr %s | ", inet_ntoa(curr_policy.src_ip_addr));
        }

        // Source Netmask that would be applied to the source IP address
        if (curr_policy.src_netmask != VALUE_NOT_SET)
        {
            printf("Src Netmask %s | ", inet_ntoa(curr_policy.src_netmask));
        }

        // Print source port if the value is set
        if (curr_policy.src_port != VALUE_NOT_SET)
        {
            printf("Src Port %d | ", curr_policy.src_port);
        }

        // Destination IP address the policy applies to
        if (curr_policy.dest_ip_addr != VALUE_NOT_SET)
        {
            printf("Dest IP Addr %s | ", inet_ntoa(curr_policy.dest_ip_addr));
        }

        // Destination Netmask that would be applied to the destination IP address
        if (curr_policy.dest_netmask != VALUE_NOT_SET)
        {
            printf("Dest Netmask %s | ", inet_ntoa(curr_policy.dest_netmask));
        }

        // Print destination port if the value is set
        if (curr_policy.dest_port != VALUE_NOT_SET)
        {
            printf("Dest Port %d | ", curr_policy.dest_port);
        }

        printf("\n");
    }
} // End handle_print_command

/* 
 Helper function for parsing the protocol value from protocol_input parameter
 If it is one of ALL, TCP, UDP, or ICMP protocol it'll set it on the policy
 Otherwise it'll call invalid_input()
*/
void parse_protocol(char *protocol_input, firewall_policy_t *policy)
{
    // Check and set which protocol the policy should apply to
    if (strcmp(protocol_input, PROTO_ALL) == 0)
    {
        if (logPtr != NULL)
        {
          fprintf(logPtr, "\nParsing, TCP, UDP, and ICMP protocols called\n"); 
        }
        policy->protocol = IPPROTO_ALL;
    }
    else if (strcmp(protocol_input, PROTO_TCP) == 0)
    {
        if (logPtr != NULL)
        {
          fprintf(logPtr, "\nParsing, TCP called\n"); 
        }
        policy->protocol = IPPROTO_TCP; 
    }
    else if (strcmp(protocol_input, PROTO_UDP) == 0)
    {
        if (logPtr != NULL)
        {
          fprintf(logPtr, "\nParsing, UDP called\n"); 
        }
        policy->protocol = IPPROTO_UDP;
    }
    else if (strcmp(protocol_input, PROTO_ICMP) == 0)
    {   
        if (logPtr != NULL)
        {
          fprintf(logPtr, "\nParsing, ICMP called\n"); 
        }
        policy->protocol = IPPROTO_ICMP;
    }
    else 
    {
        invalid_input();
    }
} // End parse_protocol

/* 
 Helper function for parsing the action value from action_input parameter
 If it is one of UNBLOCK or BLOCK strings it'll set it on the policy
 Otherwise it'll call invalid_input()
*/
void parse_action(char *action_input, firewall_policy_t *policy)
{
    // Check and set the action that should be used for the policy
    if (strcmp(action_input, ACTION_BLOCK) == 0)
    {
        if (logPtr != NULL)
        {
          fprintf(logPtr, "\nParsing, BLOCK action invocation\n"); 
        }
        policy->action = BLOCK;
    }
    else if (strcmp(action_input, ACTION_UNBLOCK) == 0)
    {
        if (logPtr != NULL)
        {
          fprintf(logPtr, "\nParsing, UNBLOCK action invocation\n"); 
        }
        policy->action = UNBLOCK;
    }
    else 
    {
       invalid_input();
    }
} // End parse_action

/* 
 Helper function for parsing the source port value from src_port_input parameter
 If it is a positive port number it'll set it on the policy
 Otherwise it'll call invalid_input()
*/
void parse_source_port(char *src_port_input, firewall_policy_t *policy)
{
    u16_t port = atoi(src_port_input);

    // Port has to be a positive number to be considered valid
    if (port <= 0)
    {
        invalid_input();
    }

    if (logPtr != NULL)
    {
       fprintf(logPtr, "\nParsing source, %d port\n", port); 
    }
    policy->src_port = port;
} // End parse_source_port

/* 
 Helper function for parsing the destination port value from dest_port_input parameter
 If it is a positive port number it'll set it on the policy
 Otherwise it'll call invalid_input()
*/
void parse_dest_port(char *dest_port_input, firewall_policy_t *policy)
{
    int port = atoi(dest_port_input);

    // Port has to be a positive number to be considered valid
    if (port <= 0)
    {
        invalid_input();
    }

    if (logPtr != NULL)
    {
       fprintf(logPtr, "\nParsing destination %d port\n", port); 
    }
    policy->dest_port = port;
} // End parse_dest_port

/* 
 Helper function to check if there is an invalid netmask set. Which means if the netmask is set and the ip address
 is not.
 Returns 1 if invalid, 0 if valid setup 
*/
int invalid_netmask_set(int netmask_set, int ip_addr_set)
{
    return netmask_set && !ip_addr_set;
} // End invalid_netmask_set

/* 
 Helper function to check if there is an invalid port setup. Which means that the source or destination is set
 when the protocol is either ALL or ICMP.
 Returns 1 if invalid, 0 if valid setup
*/
int invalid_port_setups(int protocol, int src_port_set, int dest_port_set)
{
    // If the protocol is ALL, or ICMP then the port for source or destination can't be set.
    int deny_ports_set = protocol == IPPROTO_ALL || protocol == IPPROTO_ICMP;
    int either_port_set = src_port_set || dest_port_set;

    return deny_ports_set && either_port_set;
} // End invalid_port_setups

/* 
 Handles adding a policy to the firewall.
 Goes through args and build a policy based on the provided values, 
 if there is a missing value for a policy criteria
 or if there is unexpected values then the policy will not be added.
 Expects that there is at least a protocol, and an action. Everything else is optional, if there is a netmask
 then there must be a corresponding IP address for source or destination.
 Port numbers are not allowed if the protocol is ALL or ICMP.
*/
void handle_add_command(int num_args, char *args[], int packet_type, int ip_fd)
{
    // Number of args has to be an even number as each criteria will have a value associated with it
    // And there has to enough args to cover the expected values from protocol, action, and in/outgoing packet type
    if (num_args % 2 != 0 || num_args < MIN_NUM_ARGS_ADD_COMMAND)
    {
        invalid_input();
    }
    
    if (logPtr != NULL)
    {
       fprintf(logPtr, "\nAdd command invoked\n"); 
    }

    firewall_policy_t policy;

    // Set values to defaults
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

    /* 
     Goes through each arg and adds it to the policy.
     If there are duplicate criterias (such as protocol), non-positive port numbers, or invalid
     values for a criteria then it will print the usage and return out of this function.
     critieria_pos and value_pos are incremented by 2 every loop as a criteria and its value are checked 
     at the same time.
    */
    while (criteria_pos < num_args && value_pos < num_args)
    {
        if (strcmp(args[criteria_pos], PROTO) == 0) 
        {
            // Protocol was already set, therefore invalid input
            if (protocol_set)
            {
                invalid_input();
            }
            
            // Attempts to parse the protocol contained at value_pos
            parse_protocol(args[value_pos], &policy);
            protocol_set = 1;
        } 
        else if (strcmp(args[criteria_pos], ACTION) == 0) 
        {
            // Action was already set, therefore invalid input
            if (policy.action != VALUE_NOT_SET)
            {
                invalid_input();
            }   

            parse_action(args[value_pos], &policy);
        } 
        else if (strcmp(args[criteria_pos], SRC_IP) == 0) 
        {
            // Source IP was already set, therefore invalid input
            if (src_ip_set)
            {
                invalid_input();
            }  

            if(!inet_aton(args[value_pos], &(policy.src_ip_addr)))
            {
                invalid_input();
            } 

            src_ip_set = 1;
        }
        else if (strcmp(args[criteria_pos], SRC_NETMASK) == 0) 
        {
            // Source netmask was already set, therefore invalid input
            if (src_netmask_set)
            {
                invalid_input();
            }  

            if(!inet_aton(args[value_pos], &(policy.src_netmask)))
            {
                invalid_input();
            } 

            src_netmask_set = 1;
        }
        else if (strcmp(args[criteria_pos], SRC_PORT) == 0) 
        {
            // Source port was already set, therefore invalid input
            if (src_port_set)
            {
                invalid_input();
            }  

            parse_source_port(args[value_pos], &policy);
            src_port_set = 1;
        }
        else if (strcmp(args[criteria_pos], DEST_IP) == 0) 
        {
            // Destination IP was already set, therefore invalid input
            if (dest_ip_set)
            {
                invalid_input();
            }  

            if(!inet_aton(args[value_pos], &(policy.dest_ip_addr)))
            {
                invalid_input();
            } 

            dest_ip_set = 1;
        }
        else if (strcmp(args[criteria_pos], DEST_NETMASK) == 0) 
        {
            // Destination netmask was already set, therefore invalid input
            if (dest_netmask_set)
            {
                invalid_input();
            }  

            if(!inet_aton(args[value_pos], &(policy.dest_netmask)))
            {
                invalid_input();
            } 

            dest_netmask_set = 1;
        }
        else if (strcmp(args[criteria_pos], DEST_PORT) == 0) 
        {
            // Destination port was already set, therefore invalid input
            if (dest_port_set)
            {
                invalid_input();
            }  

            parse_dest_port(args[value_pos], &policy);
            dest_port_set = 1;
        }
        else 
        {
            invalid_input();
        }

        // Increment by 2 since we parse 2 positions at a time, one for the criteria type and the other for the value
        criteria_pos += 2;
        value_pos += 2;
    }

    // If the protocol wasn't set, action wasn't set, if there an invalid netmask, or an invalid port set
    // then there was invalid input
    if (!protocol_set ||
        invalid_netmask_set(src_netmask_set, src_ip_set) ||
        invalid_netmask_set(dest_netmask_set, dest_ip_set) ||
        invalid_port_setups(policy.protocol, src_port_set, dest_port_set) ||
        policy.action == VALUE_NOT_SET)
    {
        invalid_input();
    }

    int result = ioctl(ip_fd, FIREWALLPOLICYADD, &policy);

    if (result == -1)
    { 
        printf("failed ioctl call \n");
        if (logPtr != NULL) 
        {
          fprintf(logPtr, "\nfailed ioctl call \n");
        }
        
    }
} // End handle_add_command

/* 
 Checks the passed in args for if there is a valid command to be executed
 If so, it'll call the appropriate function to handle it
 Otherwise it'll print the expected usage for the program
*/
void check_args_for_command(int num_args, char *args[])
{
    int ip_fd = get_ip_fd();
    
    // Check if user is using debug mdoe with no additional commands
    if (args[ARGS_EXPECTED_COMMAND_POS] == NULL)
    {
        if (logPtr != NULL)
        {
          fprintf(logPtr, "\nPlease use debug mode in conjunction with other commands\n");
        }
        else 
        {
          printf("\nPlease use debug mode in conjunction with other commands\n");
        }
        exit(1);
    }

    /* 
     Check the command that was passed in the args
     If there was a command, call the appropriate function to handle it, otherwise
     print the expected usage for this program 
    */
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
    else if (strcmp(args[ARGS_EXPECTED_COMMAND_POS], TEST_POLICIES) == 0)
    {
        handle_test_command(num_args, args, ip_fd);
    }
    else 
    {
        invalid_input();
    }
} // End check_args_for_command

int main(int argc, char *argv[])
{
    if (argc < MIN_NUMBER_ARGS) 
    {
        invalid_input();
    }

    initLogging();
    check_args_for_command(argc, argv);
    
    if (logPtr != NULL)
    {
      fclose(logPtr);
    }

    return(0);
} // End main
