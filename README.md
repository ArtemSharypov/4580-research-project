# Welcome to our Comp 4580 Computer Security Research Project for the Winter 2020 term
Creators: Artem Sharypov & Adam Salsi

Topic: Firewalls

In addition to rsearch on the topic, the main deliverable for this project is the completion of the following SEED seceurity lab: http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Networking/Firewall_Minix/Firewall_Minix.pdf

For detailed information on the topic please refer to our project report included in this repository.
We had a lot of completing this lab and I hope you enjoy the content we've provided :) 

# Setup the Minix environment & Project 
 1. Download Minix at the following location: http://download.minix3.org/iso/minix_R3.3.0-588a35b.iso.bz2
 2. Download MobaXTerm at the following location: https://mobaxterm.mobatek.net/download.html
 3. Download Virtual Box at the following lcoation: https://www.virtualbox.org/wiki/Downloads
 4. Setup a Minix virtual environment using the iso you just downloaded. There are guides to this online including the following one: 
    https://gist.github.com/Drowze/2f7cbce35ade1fa94b2511f4138a32c2
 5. Make sure SSH is installed on your Minix OS and follow the guide above to setup SSH using MobaxTerm 
 6. Clone this repo and ensure you can obtain root access to your Minix machine via SSH
 7. Clone minix into your Minix machine using the git package, this will add /usr/src/...
 8. Move the following files as follows into their respective locations in /usr/src/... :
      - ip_ioctl.c, ip_read.c, ip_write.c to /usr/src/minix/net/inet/generic/
      - policy_filter.c and policy_filter.h to /usr/src/minix/net/inet/generic and add it to the Makefile in the previous folder
      - ioc_net.h to /usr/src/minix/include/sys/
      - firewall_def.h to /usr/src/minix/include/net/gen and add it to the Makefile in same folder
      - minifirewall.c & makefile to /usr/src/minix/commands/minifirewall (create the directory if it doesn't exist) 
      - modify makefile in /usr/src/minix/commands to include minifirewall
      - Move firewallTestIn.sh & firewallTestOut.sh into the following directory ->  ../usr/src/minix/commands/minifirewall
 9. Run Make build (Builds the changes you just made)
 10. Run Make install (This updates the kernal commands to include the minifirewall)
 
 You should now have the 'minifirewall' setup on your Minix environment. 

# Using the firewall

  We access the firewall directly by invoking the 'minifirewall' command. Below are examples of some simple commands to get you started. Please view the project report or simply invoke the 'minifirewall' command without parameters for a more detailed explanation on command usage.
  
   1. To print all of your currently configured rules:
   
          minifirewall --print
          
   2. To Block all incoming packets
   
          minifirewall --in --proto -ALL --action BLOCK
          
   3. To block all outgoing packets
   
          minifirewall --in --proto -ALL --action BLOCK
          
   4. To block incoming packets from a specific IP (Ex: 127.0.0.2)
   
          minifirewall --in --srcip 127.0.0.2 --proto TCP --destport 80 --action BLOCK
          
   5. To delete a policy (Ex: policy #1)
   
          minifirewall --delete 1
   
# Testing the Firewall

  To execute the firewall test/validation script invoke the following command:
  
      minifirewall --test
    
