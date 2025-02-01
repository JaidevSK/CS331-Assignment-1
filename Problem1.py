"""
1. Find the total amount of data transferred (in bytes), the total number of packets transferred, and the 
minimum, maximum, and average packet sizes. Also, show the distribution of packet sizes (e.g., by 
plotting a histogram of packet sizes). 
2. Find unique source-destination pairs (source IP:port and destination IP:port)  in the captured data. 
3. Display a dictionary where the key is the IP address and the value is the total flows for that IP address 
as the source. Similarly display a dictionary where the key is the IP address and the value is the total 
flows for that IP address as the destination. Find out which source-destination (source IP:port and 
destination IP:port) have transferred the most data. 
4. List the top speed in terms of `pps` and `mbps` that your program is able to capture the content without 
any loss of data when i) running both tcpreplay and your program on the same machine (VM), and ii) 
when running on different machines: Two student group should run the program on two different 
machines eg. tcpreplay on physical-machine of student1 and sniffer program physical-machine of 
student2. Single students should run between two VMs.    
"""

import socket
import struct
import time
import matplotlib.pyplot as plt
import signal

ctr = 0
amt_of_data = 0
packets_sizes = []
source_dest_pairs = {}
source_flows = {}
dest_flows = {}
source_dest_data_transfer = {}

time_start = time.time()




def sinff_fn():
    global ctr, amt_of_data, packets_sizes, source_dest_pairs, source_flows, dest_flows, source_dest_data_transfer
    raw_data, addr = RawSock.recvfrom(65536)
    # https://en.wikipedia.org/wiki/Ethernet_frame
    dest_mac, src_mac, eth_proto = raw_data[:6], raw_data[6:12], raw_data[12:14]

    ctr+=1
    print("Current Counter = ", ctr)
    amt_of_data += len(raw_data) # Total amount of data transferred
    packets_sizes.append(len(raw_data)) # Packet sizes

    if eth_proto == b'\x08\x00':

        ipv4_data = raw_data[14:]
        # https://en.wikipedia.org/wiki/IPv4
        _, tos, total_length, identification, _flagsandoffset, ttl, proto, checksum, src_addr, dest_addr = struct.unpack('!BBHHHBBHII', ipv4_data[:20])

        src_addr = '.'.join(map(str, src_addr.to_bytes(4, byteorder='big')))
        dest_addr = '.'.join(map(str, dest_addr.to_bytes(4, byteorder='big')))

        if (src_addr, dest_addr) in source_dest_pairs:
            source_dest_pairs[(src_addr, dest_addr)] += 1
        else:
            source_dest_pairs[(src_addr, dest_addr)] = 1

        if src_addr in source_flows:
            source_flows[src_addr] += 1
        else:
            source_flows[src_addr] = 1

        if dest_addr in dest_flows:
            dest_flows[dest_addr] += 1
        else:
            dest_flows[dest_addr] = 1


        
        if proto == 6:
            tcp_data = ipv4_data[20:]
            # https://en.wikipedia.org/wiki/Transmission_Control_Protocol
            src_port, dest_port, sequence, ack, offset_reserved_flags, window, checksum, urg = struct.unpack('!HHIIHHHH', tcp_data[:20])
            offset_val = (offset_reserved_flags >> 12) * 4 # It should always be a multiple of 4
            tcp_actual_data = tcp_data[offset_val:]
            # print('\nTCP Packet:')
            # print("  |--->" + 'Source Address: {}, Destination Address: {}'.format(src_addr, dest_addr))
            # print("  |--->" + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
            # print("  |--->" + 'Sequence: {}, Acknowledgment: {}'.format(sequence, ack))
            # print("  |--->" + 'Window: {}, Checksum: {}'.format(window, checksum))
            # print("  |--->" + 'Data: {}'.format(tcp_actual_data))

            if ((src_addr, src_port), (dest_addr, dest_port)) in source_dest_data_transfer:
                source_dest_data_transfer[((src_addr, src_port), (dest_addr, dest_port))] += len(raw_data)
            else:
                source_dest_data_transfer[((src_addr, src_port), (dest_addr, dest_port))] = len(raw_data)


        elif proto == 17:
            udp_data = ipv4_data[20:]
            # https://en.wikipedia.org/wiki/User_Datagram_Protocol
            src_port, dest_port, length, checksum = struct.unpack('!HHHH', udp_data[:8])
            udp_actual_data = udp_data[8:]
            # print('\nUDP Packet:')
            # print("  |--->" + 'Source Address: {}, Destination Address: {}'.format(src_port, dest_port))
            # print("  |--->" + 'Source Port: {}, Destination Port: {}'.format(src_addr, dest_addr))
            # print("  |--->" + 'Length: {}, Checksum: {}'.format(length, checksum))
            # print("  |--->" + 'Data: {}'.format(udp_actual_data))

        elif proto == 1:
            icmp_data = ipv4_data[20:]
            # https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
            type_, code, checksum = struct.unpack('!BBH', icmp_data[:4])
            icmp_actual_data = icmp_data[4:]
            # print('\nICMP Packet:')
            # print("  |--->" + 'Type: {}, Code: {}'.format(type_, code))
            # print("  |--->" + 'Checksum: {}'.format(checksum))
            # print("  |--->" + 'Data: {}'.format(icmp_actual_data))

        else:
            pass
    
    elif eth_proto == b'x86\xdd':
        ipv6_data = raw_data[14:]
        # https://en.wikipedia.org/wiki/IPv6
        source_address = ipv6_data[8:24]
        destination_address = ipv6_data[24:40]

        # Formatting the source and destination addresses
        source_address = ':'.join(map(str, source_address.hex()))
        destination_address = ':'.join(map(str, destination_address.hex()))

        # print('\nIPv6 Packet:')
        # print("  |--->" + 'Source Address: {}, Destination Address: {}'.format(source_address, destination_address))


        if (src_addr, dest_addr) in source_dest_pairs:
            source_dest_pairs[(src_addr, dest_addr)] += 1
        else:
            source_dest_pairs[(src_addr, dest_addr)] = 1

        if src_addr in source_flows:
            source_flows[src_addr] += 1
        else:
            source_flows[src_addr] = 1

        if dest_addr in dest_flows:
            dest_flows[dest_addr] += 1
        else:
            dest_flows[dest_addr] = 1

        if (src_addr, dest_addr) in source_dest_data_transfer:
            source_dest_data_transfer[(src_addr, dest_addr)] += len(raw_data)
        else:
            source_dest_data_transfer[(src_addr, dest_addr)] = len(raw_data)        


try:
    RawSock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
except socket.error:
    print('There was an error in creating the socket')

print('Socket created')



print('Starting to capture packets...')



class TimeoutExpired(Exception):
    pass

def alarm_handler(signum, frame):
    raise TimeoutExpired



while True:
    signal.signal(signal.SIGALRM, alarm_handler)
    signal.alarm(5)

    try:
        sinff_fn()
    except TimeoutExpired:
        break


time_end = time.time()-5

print('Total Packets: ', ctr)
print('Total Amount of Data Transferred: ', amt_of_data, ' Bytes')
print('Minimum Packet Size: ', min(packets_sizes))
print('Maximum Packet Size: ', max(packets_sizes))
print('Average Packet Size: ', sum(packets_sizes) / len(packets_sizes))
plt.hist(packets_sizes, bins=10)
plt.show()
print('Source Destination Pairs: ', source_dest_pairs.keys())
print('Source Flows: ', source_flows)
print('Destination Flows: ', dest_flows)
print('Source Destination Data Transfer: ', source_dest_data_transfer)
print('Maximum Data Transfer: ', max(source_dest_data_transfer, key=source_dest_data_transfer.get))
print('Time taken: ', time_end - time_start)
print('pps: ', ctr / (time_end - time_start))
print('mBps: ', amt_of_data / (time_end - time_start) / 1000000)

# Saving all this data to a file called results.txt
with open('Problem1_results1.txt', 'w') as f:
    f.write('Total Packets: ' + str(ctr) + '\n')
    f.write('Total Amount of Data Transferred: ' + str(amt_of_data) + ' Bytes\n')
    f.write('Minimum Packet Size: ' + str(min(packets_sizes)) + '\n')
    f.write('Maximum Packet Size: ' + str(max(packets_sizes)) + '\n')
    f.write('Average Packet Size: ' + str(sum(packets_sizes) / len(packets_sizes)) + '\n')


    # f.write('Source Destination Pairs: ' + str(source_dest_pairs.keys()) + '\n')

with open('Problem1_results2.txt', 'w') as f:
    # f.write('Source Destination Data Transfer: ' + str(source_dest_data_transfer) + '\n')
    for key in source_dest_data_transfer:
        f.write('Source: ' + str(key[0]) + ' Destination: ' + str(key[1]) + '\n')

with open('Problem1_results3.txt', 'w') as f:
    f.write('Source Flows: ' + str(source_flows) + '\n')
    f.write('Destination Flows: ' + str(dest_flows) + '\n')
    f.write('Maximum Data Transfer: ' + str(max(source_dest_data_transfer, key=source_dest_data_transfer.get)[0]) + str(max(source_dest_data_transfer, key=source_dest_data_transfer.get)[1]) + '\n')

with open('Problem1_results4.txt', 'w') as f:
    f.write('Time taken: ' + str(time_end - time_start) + '\n')
    f.write('pps: ' + str(ctr / (time_end - time_start)) + '\n')
    f.write('mBps: ' + str(amt_of_data / (time_end - time_start) / 1000000) + '\n')
# Save the plt.figure to png
plt.hist(packets_sizes, bins=10)
plt.savefig('Problem1_histogram.png')
plt.close()
    



