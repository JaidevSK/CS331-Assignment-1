# Assignment 1 - Computer Networks
## Packet Sniffer

### Directions for Usage
 This also contains the test script

 - Open Ubuntu Terminal
 - Navigate to the folder contatining 4.pcap
 - Run the command
 ```
 sudo tcpreplay -i eth0 -v --mbps 15 4.pcap
 ```
 This mbps value has to be calibrated to ensure no packet is lost.
 If this does not work, run it on the interface that is up. This can be found using:
 ```
 ifconfig
 ```
Before that, open another terminal and move to the folder where the code files are stored.
```
sudo python3 Problem1.py
```
Make sure that you execute the Problem1.py program immediately before the tcpreplay command as it will be "automatically deactivated" after 5 seconds of inactivity.

For problem 2, run the following command:
```
sudo python3 Problem2.py
```

I have also created two bash files called:
- tester1.sh : For Problem 1
- tester2.sh : For Problem 2

They can be run directly by bash _filename_.sh
But ensure that both 4.pcap and the code files are in the same folder.

If the bash files do not work due to synchronisation errors or if all the packets are not captured, either try to change the value of mbps in bash or follow the instructions given in the beginning to run the code separately.


### System Requirements
- Ubuntu OS (24.04)
- Python 3.12 
- tcpreplay installed
- net-tools installed