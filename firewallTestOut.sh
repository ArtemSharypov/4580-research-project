#!/bin/sh
# Run the minifirewall test suite
# Test print minifirewall
readonly TEST_PATH=testResults/testTerminalOutputOut.txt
readonly EXTRA_LOGS=testResults/extraLogs.txt
rm TEST_PATH
rm EXTRA_LOGS
###############################################################################################
print_result() {
  if [ $? == 0 ]; then 
    printf "Successful connection attempt, there was no block\n" &>> $TEST_PATH 
  else  
    printf "Failed to connect, likely due to a block...that darn firewall\n" &>> $TEST_PATH
  fi
}
###############################################################################################
echo "---------------------------------------------------------------------------"
printf "Testing traffic manipulation of outgoing packets\n" &>> $TEST_PATH
printf "\n\n" &>> $TEST_PATH
echo "Test minifirewall policy Blocks OUT" &>> $TEST_PATH
echo "----------------------------------" &>> $TEST_PATH
# Test #1
printf "\nTest #1 TCP block outgoing \n" 2>&1 | tee -a $TEST_PATH
(sleep 5; echo "Succesfully Recieved the TCP message" | nc -w 1 localhost 80) | nc -w 10 -l -p 80 &>> $EXTRA_LOGS
print_result
printf "\nminifirewall --out --proto TCP --action BLOCK\n" &>> $TEST_PATH
minifirewall --out --proto TCP --action BLOCK
(sleep 5; echo "Succesfully Recieved the TCP message" | nc -w 1 localhost 80) | nc -w 10 -l -p 80 &>> $EXTRA_LOGS
print_result
printf "\nminifirewall --delete 1\n" &>> $TEST_PATH
minifirewall --delete 1 &>> $TEST_PATH
###############################################################################################
# Test #2
printf "\nTest #2 UDP block outgoing \n" 2>&1 | tee -a $TEST_PATH
printf "\n Progress...................64/100\n"
(sleep 5; echo "Succesfully Recieved the message" | nc -u -w 1 localhost 80) | nc -w 10 -u -l -p 80 &>> $EXTRA_LOGS
print_result
printf "\nminifirewall --out --proto UDP --action BLOCK\n" &>> $TEST_PATH
minifirewall --out --proto UDP --action BLOCK
(sleep 5; echo"Succesfully Recieved the message" | nc -u -w 1 localhost 80) | nc -w 10 -u -l -p 80 $EXTRA_LOGS
print_result
printf "\nminifirewall --delete 1\n" &>> $TEST_PATH
minifirewall --delete 1 &>> $TEST_PATH
###############################################################################################
# Test #3
printf "\nTest #3 ICMP block outgoing \n" 2>&1 | tee -a $TEST_PATH
ping -c 1 localhost &>> $EXTRA_LOGS
print_result
printf "\nminifirewall --out --proto IDMP --action BLOCK\n" &>> $TEST_PATH
minifirewall --out --proto ICMP --action BLOCK
ping -c 1 localhost &>> $EXTRA_LOGS
print_result
printf "\nminifirewall --delete 1\n" &>> $TEST_PATH
minifirewall --delete 1 &>> $TEST_PATH
###############################################################################################
# Test #4
printf "\nTest #4 Block ALL outgoing \n" 2>&1 | tee -a $TEST_PATH
ping -c 1 localhost &>> $EXTRA_LOGS
printf "\nminifirewall --out --proto ALL --action BLOCK\n" &>> $TEST_PATH
minifirewall --out --proto ALL --action BLOCK
ping -c 1 localhost &>> $EXTRA_LOGS
print_result
(sleep 5; echo"Succesfully Recieved the message" | nc -u -w 1 localhost 80) | nc -w 10 -u -l -p 80 $EXTRA_LOGS
print_result
(sleep 5; echo "Succesfully Recieved the TCP message" | nc -w 1 localhost 80) | nc -w 10 -l -p 80 &>> $EXTRA_LOGS
print_result
printf "\nminifirewall --delete 1\n" &>> $TEST_PATH
minifirewall --delete 1 &>> $TEST_PATH
###############################################################################################
# Test #5
printf "\nTest #5 Test blockage of outgoing source IP Address \n" 2>&1 | tee -a $TEST_PATH
printf "\n Progress...................77/100\n"
ping -c 1 10.0.2.15 &>> $TEST_PATH
printf "\nminifirewall --out --srcip 10.0.2.15 --proto ALL --action BLOCK\n" &>> $TEST_PATH
minifirewall --out --srcip 10.0.2.15 --proto ALL --action BLOCK &>> $TEST_PATH
ping -c 1 10.0.2.15 &>> $TEST_PATH
printf "\nminifirewall --delete 1\n" &>> $TEST_PATH
minifirewall --delete 1 &>> $TEST_PATH
###############################################################################################
# Test #6
printf "\nTest #6 Test blockage of outgoing destination IP Address \n" 2>&1 | tee -a $TEST_PATH
printf "\n Progress...................77/100\n"
printf "\nminifirewall --out --destip 127.0.0.1 --proto TCP --destport 80 --action BLOCK\n" &>> $TEST_PATH
minifirewall --out --destip 127.0.0.1 --proto TCP --destport 80 --action BLOCK &>> $TEST_PATH
printf "\nBlocked port: \n" &>> $TEST_PATH
(sleep 5; echo "Succesfully Recieved the TCP message" | nc -w 1 127.0.0.1 80) | nc -w 10 -l -p 80 &>> $TEST_PATH
print_result
printf "\nminifirewall --delete 1\n" &>> $TEST_PATH
minifirewall --delete 1 &>> $TEST_PATH
###############################################################################################
# Test #7
printf "\nTest #7 Block outgoing packets if directed at specific port \n" 2>&1 | tee -a $TEST_PATH
printf "\n Progress...................84/100\n"
printf "\nminifirewall --out --srcip 10.0.2.15 --proto TCP --destport 80 --action BLOCK\n" &>> $TEST_PATH
minifirewall --out --srcip 10.0.2.15 --proto TCP --destport 80 --action BLOCK &>> $TEST_PATH
printf "\nBlocked port: \n" &>> $TEST_PATH
(sleep 5; echo "Succesfully Recieved the TCP message" | nc -w 1 127.0.0.1 80) | nc -w 10 -l -p 80 &>> $TEST_PATH
print_result
printf "Using alternative port we get: " &>> $TEST_PATH
(sleep 5; echo "Succesfully Recieved the TCP message" | nc -w 1 127.0.0.1 90) | nc -w 10 -l -p 90 &>> $TEST_PATH
print_result
printf "\nminifirewall --delete 1\n" &>> $TEST_PATH
minifirewall --delete 1 &>> $TEST_PATH
###############################################################################################
# Test #8
printf "\nTest #8 Test blockage of outgoing masked IP Address \n" 2>&1 | tee -a $TEST_PATH
printf "\n Progress...................88/100\n"
ping -c 1 255.255.255.255 &>> $TEST_PATH
printf "\nminifirewall --out --srcip 10.0.2.15 --srcnetmask 255.255.255.255 --proto ALL --action BLOCK\n" &>> $TEST_PATH
minifirewall --out --srcip 10.0.2.15 --srcnetmask 255.255.255.255 --proto ALL --action BLOCK &>> $TEST_PATH
ping -c 1 255.255.255.255 &>> $TEST_PATH
printf "\nminifirewall --delete 1\n" &>> $TEST_PATH
minifirewall --delete 1 &>> $TEST_PATH
###############################################################################################
# Test #9
printf "\nTest #9 Test Unblock outgoing policy \n" 2>&1 | tee -a $TEST_PATH
printf "\n Progress...................95/100\n"
printf "\nminifirewall --out --proto TCP --action BLOCK\n" &>> $TEST_PATH
minifirewall --out --proto TCP --action BLOCK &>> $TEST_PATH
(sleep 5; echo "Succesfully Recieved the TCP message" | nc -w 1 127.0.0.1 80) | nc -w 10 -l -p 80 &>> $EXTRA_LOGS
print_result
printf "\nminifirewall --out --proto TCP --action UNBLOCK\n" &>> $TEST_PATH
minifirewall --out --proto TCP --action UNBLOCK &>> $TEST_PATH
(sleep 5; echo "Succesfully Recieved the TCP message" | nc -w 1 127.0.0.1 80) | nc -w 10 -l -p 80 &>> $EXTRA_LOGS
print_result
printf "\nminifirewall --delete 2\n" &>> $TEST_PATH
minifirewall --delete 2 &>> $TEST_PATH
printf "\nminifirewall --delete 1\n" &>> $TEST_PATH
minifirewall --delete 1 &>> $TEST_PATH
###############################################################################################
printf "\n Progress...................100/100\n"
printf "\n\n\n" &>> $TEST_PATH
printf "\n Output tests completed view in /testResults/testTerminalOutputOut.txt\n"
printf "\n All tests completed thank you for your patience! :)"
