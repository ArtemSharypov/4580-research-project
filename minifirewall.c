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

        policy.is_ingoing_packet = 1;
        policy.block = 1;
        policy.protocol = ALL;

        //fake ioctl call
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

        int policyNumToRemove = 5;

        //fake ioctl call
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

        //fake ioctl call
        //todo check if we can do NULL
        result = ioctl(ip_fd, FIREWALLPOLICYPRINT, NULL);

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