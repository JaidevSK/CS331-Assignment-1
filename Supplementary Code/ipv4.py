import socket
import struct # https://stackoverflow.com/questions/11826054/valueerror-invalid-literal-for-int-with-base-16-x0e-xa3-python

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
        
        if proto in protocols_set1:
            protocols_set1[proto] += 1
        else:
            protocols_set1[proto] = 1

        print('\nIPv4 Packet:')
        print("  |--->" + 'Total Length: {}, Checksum: {}, Protocol: {}'.format(total_length, checksum, proto))
        print("  |--->" + 'Source Address: {}, Destination Address: {}'.format(src_addr, dest_addr))
        print("  |--->" + 'Protocols Set: ', protocols_set1)










### RESULTS ####################
#   |--->Protocols Set:  {6: 634409, 17: 152739, 1: 4266, 2: 286, 13: 1, 170: 8, 99: 1, 221: 1, 89: 1, 121: 1, 53: 1, 7: 1}
################################

################################
# https://en.wikipedia.org/wiki/IPv4
# 1	Internet Control Message Protocol	ICMP
# 6	Transmission Control Protocol	TCP
# 17 User Datagram Protocol	UDP
# Remaining are insignificant
################################
