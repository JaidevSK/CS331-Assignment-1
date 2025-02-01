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

    if eth_proto == b'\x08\x00':

        ipv4_data = raw_data[14:]
        # https://en.wikipedia.org/wiki/IPv4
        # Using the struct module to unpack the data
        _, tos, total_length, identification, _flagsandoffset, ttl, proto, checksum, src_addr, dest_addr = struct.unpack('!BBHHHBBHII', ipv4_data[:20])

        src_addr = '.'.join(map(str, src_addr.to_bytes(4, byteorder='big')))
        dest_addr = '.'.join(map(str, dest_addr.to_bytes(4, byteorder='big')))
        
        if proto == 6:
            tcp_data = ipv4_data[20:]
            # https://en.wikipedia.org/wiki/Transmission_Control_Protocol
            src_port, dest_port, sequence, ack, offset_reserved_flags, window, checksum, urg = struct.unpack('!HHIIHHHH', tcp_data[:20])
 

            offset_val = (offset_reserved_flags >> 12) * 4 # It should always be a multiple of 4
            tcp_actual_data = tcp_data[offset_val:]

            print('\nTCP Packet:')
            print("  |--->" + 'Source Address: {}, Destination Address: {}'.format(src_addr, dest_addr))
            print("  |--->" + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
            print("  |--->" + 'Sequence: {}, Acknowledgment: {}'.format(sequence, ack))
            print("  |--->" + 'Window: {}, Checksum: {}'.format(window, checksum))
            print("  |--->" + 'Data: {}'.format(tcp_actual_data))

        if proto == 17:
            udp_data = ipv4_data[20:]
            # https://en.wikipedia.org/wiki/User_Datagram_Protocol
            src_port, dest_port, length, checksum = struct.unpack('!HHHH', udp_data[:8])
            udp_actual_data = udp_data[8:]
            print('\nUDP Packet:')
            print("  |--->" + 'Source Address: {}, Destination Address: {}'.format(src_port, dest_port))
            print("  |--->" + 'Source Port: {}, Destination Port: {}'.format(src_addr, dest_addr))
            print("  |--->" + 'Length: {}, Checksum: {}'.format(length, checksum))
            print("  |--->" + 'Data: {}'.format(udp_actual_data))

        if proto == 1:
            icmp_data = ipv4_data[20:]
            # https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
            type_, code, checksum = struct.unpack('!BBH', icmp_data[:4])
            icmp_actual_data = icmp_data[4:]
            print('\nICMP Packet:')
            print("  |--->" + 'Type: {}, Code: {}'.format(type_, code))
            print("  |--->" + 'Checksum: {}'.format(checksum))
            print("  |--->" + 'Data: {}'.format(icmp_actual_data))
