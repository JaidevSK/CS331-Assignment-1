# Hiding a Message in TCP Packet Payload
# Q1.Can you extract the hidden message from the packet payload?
# Hint : Filter packet with source port 1579  search keyword CS331.
# Q2.How many packets contain the hidden message?
# Q3.What protocol is used to transmit the packet containing the hidden message?
# Q4.What is the checksum of the TCP segment containing the hidden message?


import socket
import struct
import signal



try:
    RawSock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
except socket.error:
    print('There was an error in creating the socket')

print('Socket created')



print('Starting to capture packets...')

ctr = 0
hidden_messages = []
hidden_protocol = []
checksums = []



def sinff_fn():
    global ctr, hidden_messages, hidden_protocol, checksums
    raw_data, addr = RawSock.recvfrom(65536)
    # https://en.wikipedia.org/wiki/Ethernet_frame
    dest_mac, src_mac, eth_proto = raw_data[:6], raw_data[6:12], raw_data[12:14]

    ctr+=1
    print("Current Counter = ", ctr)

    if eth_proto == b'\x08\x00':

        ipv4_data = raw_data[14:]
        # https://en.wikipedia.org/wiki/IPv4
        _, tos, total_length, identification, _flagsandoffset, ttl, proto, checksum, src_addr, dest_addr = struct.unpack('!BBHHHBBHII', ipv4_data[:20])

        src_addr = '.'.join(map(str, src_addr.to_bytes(4, byteorder='big')))
        dest_addr = '.'.join(map(str, dest_addr.to_bytes(4, byteorder='big')))

        
        if proto == 6:
            tcp_data = ipv4_data[20:]
            # https://en.wikipedia.org/wiki/Transmission_Control_Protocol
            src_port, dest_port, sequence, ack, offset_reserved_flags, window, checksum, urg = struct.unpack('!HHIIHHHH', tcp_data[:20])
            offset_val = (offset_reserved_flags >> 12) * 4 # It should always be a multiple of 4
            tcp_actual_data = tcp_data[offset_val:]

            if src_port == 1579:
                if 'CS331' in tcp_actual_data.decode('utf-8'):
                    hidden_messages.append(tcp_actual_data)
                    hidden_protocol.append(proto)
                    checksums.append(checksum)
                    print('\nHidden Message Found TCP:')
                    print("  |--->" + 'Data: {}'.format(tcp_actual_data))
                    print("  |--->" + 'Checksum: {}'.format(checksum))
                    print("  |--->" + 'Protocol: {}'.format(proto))

        elif proto == 17:
            udp_data = ipv4_data[20:]
            # https://en.wikipedia.org/wiki/User_Datagram_Protocol
            src_port, dest_port, length, checksum = struct.unpack('!HHHH', udp_data[:8])
            udp_actual_data = udp_data[8:]

            if src_port == 1579:
                if 'CS331' in udp_actual_data.decode('utf-8'):
                    hidden_messages.append(udp_actual_data)
                    hidden_protocol.append(proto)
                    checksums.append(checksum)
                    print('\nHidden Message Found UDP:')
                    print("  |--->" + 'Data: {}'.format(udp_actual_data))
                    print("  |--->" + 'Checksum: {}'.format(checksum))
                    print("  |--->" + 'Protocol: {}'.format(proto))

        elif proto == 1:
            icmp_data = ipv4_data[20:]
            # https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
            type_, code, checksum = struct.unpack('!BBH', icmp_data[:4])
            icmp_actual_data = icmp_data[4:]

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


print('Finished capturing packets...')
print('Hidden Messages: ', hidden_messages)
print('Hidden Protocols: ', hidden_protocol)
print('Checksums: ', checksums)
print('Total Number of Hidden Messages:', len(hidden_messages))

# Save this as text files
with open('Problem2_HiddenMessages.txt', 'w') as f:
    for item in hidden_messages:
        f.write("%s\n" % item)

with open('Problem2_HiddenProtocols.txt', 'w') as f:
    for item in hidden_protocol:
        f.write("%s\n" % item)

with open('Problem2_Checksums.txt', 'w') as f:
    for item in checksums:
        f.write("%s\n" % item)

            



