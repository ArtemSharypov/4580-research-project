#!/bin/sh
# Run the minifirewall test suite
# Test print minifirewall
readonly TEST_PATH=testResults/testTerminalOutputIn.txt
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
echo "Testing minifirewall"
echo "---------------------------------------------------------------------------"
printf "\n Progress...................0/100\n"
printf "\n\n" &>> $TEST_PATH
# Clear policy list
minifirewall --delete 1 &>> $TEST_PATH
minifirewall --delete 2 &>> $TEST_PATH
minifirewall --delete 3 &>> $TEST_PATH
minifirewall --delete 4 &>> $TEST_PATH
minifirewall --delete 5 &>> $TEST_PATH
minifirewall --delete 6 &>> $TEST_PATH
minifirewall --delete 7 &>> $TEST_PATH
minifirewall --delete 8 &>> $TEST_PATH
minifirewall --delete 9 &>> $TEST_PATH
minifirewall --delete 10 &>> $TEST_PATH
###############################################################################################
# Test #1
printf "\nTest #1 List Empty \n" 2>&1 | tee -a $TEST_PATH
printf "Test minifirewall is empty:  \n" &>> $TEST_PATH
minifirewall --print  &>> $TEST_PATH
###############################################################################################
# Test #2
printf "\nTest #2 Print policy list \n" 2>&1 | tee -a $TEST_PATH
printf "Test minifirewall prints policies: \n" &>> $TEST_PATH
minifirewall --in --proto TCP --action BLOCK
minifirewall --in --proto UDP --action UNBLOCK
minifirewall --out --proto ICMP --action BLOCK
printf "Should print out 3 policies....   \n" &>> $TEST_PATH
minifirewall --print &>> $TEST_PATH
printf "\nminifirewall --delete 1\n" &>> $TEST_PATH
minifirewall --delete 1 &>> $TEST_PATH
printf "\nminifirewall --delete 2\n" &>> $TEST_PATH
minifirewall --delete 2 &>> $TEST_PATH
printf "\nminifirewall --delete 3\n" &>> $TEST_PATH
minifirewall --delete 3 &>> $TEST_PATH
printf "\n\n" &>> $TEST_PATH
###############################################################################################
echo "Test minifirewall policy Blocks IN" &>> $TEST_PATH
echo "----------------------------------" &>> $TEST_PATH
###############################################################################################
# Test #3
printf "\nTest #3 TCP block incoming \n" 2>&1 | tee -a $TEST_PATH
(sleep 5; echo "Succesfully Recieved the TCP message" | nc -w 1 localhost 80) | nc -w 10 -l -p 80 &>> $EXTRA_LOGS
print_result
printf "\nminifirewall --in --proto TCP --action BLOCK\n" &>> $TEST_PATH
minifirewall --in --proto TCP --action BLOCK
(sleep 5; echo "Succesfully Recieved the TCP message" | nc -w 1 localhost 80) | nc -w 10 -l -p 80 &>> $EXTRA_LOGS
print_result
printf "\nminifirewall --delete 1\n" &>> $TEST_PATH
minifirewall --delete 1 &>> $TEST_PATH
###############################################################################################
# Test #4
printf "\nTest #4 UDP block incoming \n" 2>&1 | tee -a $TEST_PATH
printf "\n Progress...................15/100\n"
(sleep 5; echo "Succesfully Recieved the message" | nc -u -w 1 localhost 80) | nc -w 10 -u -l -p 80 &>> $EXTRA_LOGS
print_result
printf "\nminifirewall --in --proto UDP --action BLOCK\n" &>> $TEST_PATH
minifirewall --in --proto UDP --action BLOCK
(sleep 5; echo"Succesfully Recieved the message" | nc -u -w 1 localhost 80) | nc -w 10 -u -l -p 80 &>> $EXTRA_LOGS
print_result
printf "\nminifirewall --delete 1\n" &>> $TEST_PATH
minifirewall --delete 1 &>> $TEST_PATH
###############################################################################################
# Test #5
printf "\nTest #5 ICMP block incoming \n" 2>&1 | tee -a $TEST_PATH
ping -c 1 -w 5 www.google.com &>> $TEST_PATH
print_result
printf "\nminifirewall --in --proto ICMP --action BLOCK\n" &>> $TEST_PATH
minifirewall --in --proto ICMP --action BLOCK
ping -c 1 -w 5 www.google.com &>> $TEST_PATH
print_result
printf "\nminifirewall --delete 1\n" &>> $TEST_PATH
minifirewall --delete 1 &>> $TEST_PATH
###############################################################################################
# Test #6
printf "\nTest #6 Block ALL incoming packets \n" 2>&1 | tee -a $TEST_PATH
printf "\nminifirewall --in --proto ALL --action BLOCK\n" &>> $TEST_PATH
minifirewall --in --proto ALL --action BLOCK
ping -c 1 www.google.com &>> $EXTRA_LOGS
print_result
(sleep 5; echo"Succesfully Recieved the message" | nc -u -w 1 localhost 80) | nc -w 10 -u -l -p 80 $EXTRA_LOGS
print_result
(sleep 5; echo "Succesfully Recieved the TCP message" | nc -w 1 localhost 80) | nc -w 10 -l -p 80 &>> $EXTRA_LOGS
print_result
printf "\nminifirewall --delete 1\n" &>> $TEST_PATH
minifirewall --delete 1 &>> $TEST_PATH
###############################################################################################
# Test #7
printf "\n Progress...................30/100\n"
printf "\nTest #7 Block specific incoming IP \n" 2>&1 | tee -a $TEST_PATH
ping -c 1 127.0.0.2 &>> $TEST_PATH
printf "\nminifirewall --in --srcip 127.0.0.2 --proto ALL --action BLOCK\n" &>> $TEST_PATH
minifirewall --in --srcip 127.0.0.2 --proto ALL --action BLOCK &>> $TEST_PATH
ping -c 1 127.0.0.2 &>> $TEST_PATH
printf "\nminifirewall --delete 1\n" &>> $TEST_PATH
minifirewall --delete 1 &>> $TEST_PATH
###############################################################################################
# Test #8
printf "\nTest #8 Block packets if directed at specific port \n" 2>&1 | tee -a $TEST_PATH
printf "\nminifirewall --in --srcip 127.0.0.2 --proto TCP --destport 80 --action BLOCK\n" &>> $TEST_PATH
minifirewall --in --srcip 127.0.0.2 --proto TCP --destport 80 --action BLOCK &>> $TEST_PATH
(sleep 5; echo "Succesfully Recieved the TCP message" | nc -w 1 localhost 80) | nc -w 10 -l -p 80 &>> $TEST_PATH
print_result
printf "Using alternative port we get: " &>> $TEST_PATH
(sleep 5; echo "Succesfully Recieved the TCP message" | nc -w 1 localhost 90) | nc -w 10 -l -p 90 &>> $TEST_PATH
print_result
printf "\nminifirewall --delete 1\n" &>> $TEST_PATH
minifirewall --delete 1 &>> $TEST_PATH
###############################################################################################
# Test #9
printf "\n Progress...................42/100\n"
printf "\nTest #9 Test blockage of incoming masked IP Address \n" 2>&1 | tee -a $TEST_PATH
ping -c 1 255.255.255.255 &>> $TEST_PATH
printf "\nminifirewall --in --srcip 127.0.0.2 --srcnetmask 255.255.255.255 --proto ALL --action BLOCK\n" &>> $TEST_PATH
minifirewall --in --srcip 127.0.0.2 --srcnetmask 255.255.255.255 --proto ALL --action BLOCK &>> $TEST_PATH
ping -c 1 255.255.255.255 &>> $TEST_PATH
printf "\nminifirewall --delete 1\n" &>> $TEST_PATH
minifirewall --delete 1 &>> $TEST_PATH
###############################################################################################
# Test #10
printf "\nTest #10 Test Unblock incoming packet policy \n" 2>&1 | tee -a $TEST_PATH
printf "\nminifirewall --in --srcip 127.0.0.2 --proto TCP --action BLOCK\n" &>> $TEST_PATH
minifirewall --in --srcip 127.0.0.2 --proto TCP --action BLOCK &>> $TEST_PATH
(sleep 5; echo "Succesfully Recieved the TCP message" | nc -w 1 127.0.0.2 80) | nc -w 10 -l -p 80 &>> $EXTRA_LOGS
print_result
printf "\nminifirewall --in --srcip 127.0.0.2 --proto TCP --action UNBLOCK\n" &>> $TEST_PATH
minifirewall --in --srcip 127.0.0.2 --proto TCP --destport 80 --action UNBLOCK &>> $TEST_PATH
(sleep 5; echo "Succesfully Recieved the TCP message" | nc -w 1 127.0.0.2 80) | nc -w 10 -l -p 80 &>> $EXTRA_LOGS
print_result
printf "\nminifirewall --delete 1\n" &>> $TEST_PATH
minifirewall --delete 1 &>> $TEST_PATH
###############################################################################################
printf "\n Progress...................50/100\n"
printf "\n\n\n" &>> $TEST_PATH
printf  "Completed tests on incoming packets\n" &>> $TEST_PATH
