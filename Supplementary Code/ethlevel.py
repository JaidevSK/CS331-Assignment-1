import socket

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
    if eth_proto in protocols_set1:
        protocols_set1[eth_proto] += 1
    else:
        protocols_set1[eth_proto] = 1
    ctr+=1
    print('Current Protocol: ', eth_proto)
    print('Protocols Set: ', protocols_set1)
    if ctr == 792179:
        break

print('Total Protocols: ', len(protocols_set1))
print('Total Packets: ', ctr)
print('Protocols Set: ', protocols_set1)


### RESULTS #######################################
# Total Packets:  792179
# Protocols Set:  {b'\x08\x00': 791714, b'\x86\xdd': 444, b'\x08v': 1, b'\xaa\xaa': 6, b'\x08\x08': 1, b'\n\x00': 1, b'H\x00': 1, b'\x08\x10': 1, b'\x08a': 1, b'(\x00': 1, b'W\x00': 1, b'\x08%': 1, b'\x08\x9c': 1, b']%': 1, b'\x08j': 1, b's\x00': 1, b'\x9c\x00': 1, b'K\x00': 1}
###################################################

################# Based on https://en.wikipedia.org/wiki/EtherType, we can see that:
# b'\x08\x00' is IPv4
# b'\x86\xdd' is IPv6
# The rest are insignificant