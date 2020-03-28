#!/bin/sh
# Run the minifirewall test suite
readonly TEST_PATH=testResults/testTerminalOutput.txt
readonly EXTRA_LOGS=testResults/extraLogs.txt
rm TEST_PATH
rm EXTRA_LOGS
echo "---------------------------------------------------------------------------"
echo "Testing minifirewall"
echo "---------------------------------------------------------------------------"
printf "\n Progress...................0/100"
printf "\n\n" &>> $TEST_PATH
printf "Test minifirewall is empty:  \n" &>> $TEST_PATH
minifirewall --print  &>> $TEST_PATH
printf "\n\n"

print_result() {
  if [ $? == 0 ]; then 
    printf "Successful connection attempt, there was no block" &>> $TEST_PATH 
  else  
    printf "Failed to connect, likely due to a block...that darn firewall" &>> $TEST_PATH
  fi
}
echo "Test minifirewall policy Blocks IN" &>> $TEST_PATH
echo "----------------------------------" &>> $TEST_PATH
printf "\nBasic Policy\n\n" &>> $TEST_PATH
(sleep 5; echo "Succesfully Recieved the TCP message" | nc -v -w 1 localhost 80) | nc -w 10 -v -l -p 80 &>> $EXTRA_LOGS
print_result
printf "\nminifirewall --in --proto TCP --action BLOCK\n" &>> $TEST_PATH
minifirewall --in --proto TCP --action BLOCK
(sleep 5; echo "Succesfully Recieved the TCP message" | nc -v -w 1 localhost 80) | nc -v -w 10 -l -p 80 &>> $EXTRA_LOGS
print_result
printf "\nminifirewall --delete 1\n" &>> $TEST_PATH
minifirewall --delete 1 &>> $TEST_PATH
(sleep 5; echo "Succesfully Recieved the message" | nc -v -u -w 1 localhost 80) | nc -v -w 10 -u -l -p 80 &>> $EXTRA_LOGS
print_result
printf "\nminifirewall --in --proto UDP --action BLOCK\n" &>> $TEST_PATH
minifirewall --in --proto UDP --action BLOCK
(sleep 5; echo"Succesfully Recieved the message" | nc -v -u -w 1 localhost 80) | nc -v -w 10 -u -l -p 80 $EXTRA_LOGS
print_result
printf "\nminifirewall --delete 1\n" &>> $TEST_PATH
minifirewall --delete 1 &>> $TEST_PATH
ping -c 1 www.google.com &>> $EXTRA_LOGS
print_result
printf "\nminifirewall --in --proto IDMP --action BLOCK\n" &>> $TEST_PATH
minifirewall --in --proto ICMP --action BLOCK
ping -c 1 www.google.com &>> $EXTRA_LOGS
print_result
printf "\nminifirewall --delete 1\n" &>> $TEST_PATH
minifirewall --delete 1 &>> $TEST_PATH
printf "\nminifirewall --in --proto ALL --action BLOCK\n" &>> $TEST_PATH
minifirewall --in --proto ALL --action BLOCK
ping -c 1 www.google.com &>> $EXTRA_LOGS
print_result

printf "\n Progress...................20/100"

printf "\n\n\n" &>> $TEST_PATH
printf "\n Tests completed view in /testResults\n"
# Test policies:
################
