#include <sys/types.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <net/gen/firewall_def.h>
#include <net/hton.h>
#include <net/netlib.h>
#include <netdb.h>
#include <net/gen/in.h>
#include <net/gen/inet.h>
#include <net/gen/ip_io.h>

#define ADD_IN_POLICY "--in"
#define ADD_OUT_POLICY "--out"
#define DELETE_POLICY "--delete"
#define PRINT_POLICIES "--print"
#define ACTION_BLOCK "BLOCK"
#define ACTION_UNBLOCK "UNBLOCK"

void usage()
{
    // TODO
    printf("This should be used as \n");
}

// todo will need IP address format to be converted to bits? see: add_route.c

int main(int argc, char *argv[])
{
    firewall_policy_t policy;
    int ip_fd, result;
    char *ip_device = ip_device= getenv("IP_DEVICE");
    
    if (!ip_device)
        ip_device= IP_DEVICE;
    
    if (argc < 2) 
    {
        //todo remove this printf later
        printf("invalid usage \n");
        usage();   
        exit(1);
    }

    ip_fd= open(ip_device, O_RDWR);

	if (ip_fd == -1)
	{
		fprintf(stderr, "minifirewall: unable to open('%s'): %s\n", ip_device, strerror(errno));
		exit(1);
	}

    if (strcmp(argv[1], ADD_IN_POLICY) == 0 || strcmp(argv[1], ADD_OUT_POLICY) == 0) 
    {
        // policy is for in or outgoing packets
        printf ("out/ingoing packet applied to policy \n");

        policy.action = BLOCK;

        // protocols are defined as the following (which come from IP side)
        // IPPROTO_ICMP 1
        // IPPROTO_TCP 6
        // IPPROTO_UDP 17
        // and for ALL use IPPROTO_ALL
        policy.protocol = IPPROTO_ICMP;

        policy.src_ip_addr = 0;
        policy.src_netmask = 0;
        policy.dest_ip_addr = 0;
        policy.dest_netmask = 0;
        policy.dest_port = 0;
        policy.src_port = 0;

        // Simply for testing purposes
        if (strcmp(argv[1], ADD_IN_POLICY) == 0) {
            policy.packet_type = INGOING_PACKET;
        } else if (strcmp(argv[1], ADD_OUT_POLICY) == 0)
        {
            policy.packet_type = OUTGOING_PACKET;
        }

        result = ioctl(ip_fd, FIREWALLPOLICYADD, &policy);

        if (result == -1 ){ 
            printf("failed ioctl call \n");
        }
        // todo everything else
    } 
    else if (strcmp(argv[1], DELETE_POLICY) == 0) 
    {
        // delete policy
        printf("delete the specified policy \n");

        int policyNumToRemove = 1;

        result = ioctl(ip_fd, FIREWALLPOLICYREMOVE, &policyNumToRemove);

        if (result == -1 ){ 
            printf("failed ioctl call \n");
        }

        // todo
    } 
    else if(strcmp(argv[1], PRINT_POLICIES) == 0) 
    {
        // print policies
        printf("print the policies \n");

        policies_t policies;

        result = ioctl(ip_fd, FIREWALLPOLICYPRINT, &policies);

        int i;

        printf("number of policies is %d \n", policies.num_policies);

        for (i = 0; i < policies.num_policies; i++) 
        {
            printf("num is %d \n", i);
            printf("values of first is %d and %d and %d \n", policies.policies[i].packet_type, policies.policies[i].action, policies.policies[i].protocol);
        }
        
        if (result == -1 ){ 
            printf("failed ioctl call \n");
        }

        //todo
    } 
    else 
    {
        // todo
        printf("invalid input\n");
        usage();
    }

    return(0);
}