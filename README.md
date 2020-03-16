# 4580-research-project

# setup - where to move files
- ip_ioctl.c, ip_read.c, ip_write.c to /usr/src/minix/net/inet/generic/
- inet.c to /usr/src/minix/net/inet/
- ioc_net.h to /usr/src/minix/include/sys/
- firewall_def.h to /usr/src/minix/include/net/gen and add it to the Makefile in same folder
- minifirewall.c & makefile to /usr/src/minix/commands/minifirewall (create the directory if it doesn't exist) 
- modify makefile in /usr/src/minix/commands to include minifirewall
- policy_filter.c and policy_filter.h to /usr/src/minix/net/inet/generic and add it to the Makefile in the previous folder