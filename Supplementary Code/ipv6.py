import socket
import struct 

try:
    RawSock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
except socket.error:
    print('There was an error in creating the socket')

print('Socket created')

protocols_set1 = {}

ctr = 0

while True:
    raw_data, addr = RawSock.recvfrom(65536)
    # https://en.wikipedia.org/wiki/Ethernet_frame
    dest_mac, src_mac, eth_proto = raw_data[:6], raw_data[6:12], raw_data[12:14]

    ctr+=1

    if ctr == 792179:
        break

    if eth_proto == b'x86\xdd':
        ipv6_data = raw_data[14:]
        # https://en.wikipedia.org/wiki/IPv6
        # Using the struct module to unpack the data
        version_trafic_class_flow_label, payload_length_next_header_hop_limit = struct.unpack('!II', ipv6_data[:8])
        source_address = ipv6_data[8:24]
        destination_address = ipv6_data[24:40]

        print('\nIPv6 Packet:')
        print("  |--->" + 'Source Address: {}, Destination Address: {}'.format(source_address, destination_address))

