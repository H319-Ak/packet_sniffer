import socket
import struct
import textwrap

TAB_1 = '\t - '
TAB_2 = '\t\t - '
DATA_TAB = '\t\t\t - '

def main():
    print("Starting Packet Sniffer...")
    
    # Create a raw socket
    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except PermissionError:
        print("Permission denied: Run this script with root privileges.")
        return
    except Exception as e:
        print(f"Failed to create socket: {e}")
        return

    # Packet capture loop
    while True:
        try:
            raw_data, _ = conn.recvfrom(65536)
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
            print(f"\nEthernet Frame:\n{TAB_1}Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}")
            
            if eth_proto == 8:  # IPv4
                ipv4_handler(data)
            elif eth_proto == 56710:  # IPv6 placeholder
                print(f"{TAB_2}IPv6 handling not implemented.")
            else:
                print(f"{TAB_2}Unknown Protocol Data:")
                print(format_data(DATA_TAB, data))
                
        except KeyboardInterrupt:
            print("\nExiting...")
            break

def ethernet_frame(data):
    """ Unpack Ethernet frame """
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return format_mac(dest_mac), format_mac(src_mac), socket.htons(proto), data[14:]

def format_mac(bytes_addr):
    """ Format MAC address """
    return ':'.join(f'{b:02x}' for b in bytes_addr).upper()

def ipv4_handler(data):
    """ Process IPv4 packet data """
    (version, header_len, ttl, proto, src, target, data) = ipv4_unpack(data)
    print(f"{TAB_1}IPv4 Packet:\n{TAB_2}Version: {version}, Header Length: {header_len}, TTL: {ttl}")
    print(f"{TAB_2}Protocol: {proto}, Source: {src}, Target: {target}")

    # Process packet by protocol type
    if proto == 1:
        icmp_handler(data)
    elif proto == 6:
        tcp_handler(data)
    elif proto == 17:
        udp_handler(data)
    else:
        print(f"{TAB_2}Other Protocol Data:")
        print(format_data(DATA_TAB, data))

def ipv4_unpack(data):
    """ Unpack IPv4 packet header """
    ver_header_len = data[0]
    version = ver_header_len >> 4
    header_len = (ver_header_len & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_len, ttl, proto, ipv4_format(src), ipv4_format(target), data[header_len:]

def ipv4_format(addr):
    """ Format IPv4 address """
    return '.'.join(map(str, addr))

def icmp_handler(data):
    """ Process ICMP packet """
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    print(f"{TAB_1}ICMP Packet:\n{TAB_2}Type: {icmp_type}, Code: {code}, Checksum: {checksum}")
    print(f"{TAB_2}Data:")
    print(format_data(DATA_TAB, data[4:]))

def tcp_handler(data):
    """ Process TCP segment """
    src_port, dest_port, sequence, ack, offset_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_flags >> 12) * 4
    flags = {
        'URG': (offset_flags & 32) >> 5,
        'ACK': (offset_flags & 16) >> 4,
        'PSH': (offset_flags & 8) >> 3,
        'RST': (offset_flags & 4) >> 2,
        'SYN': (offset_flags & 2) >> 1,
        'FIN': offset_flags & 1,
    }
    print(f"{TAB_1}TCP Segment:\n{TAB_2}Source Port: {src_port}, Destination Port: {dest_port}")
    print(f"{TAB_2}Sequence: {sequence}, Acknowledgment: {ack}")
    print(f"{TAB_2}Flags: " + ', '.join(f"{k}: {v}" for k, v in flags.items()))
    print(f"{TAB_2}Data:")
    print(format_data(DATA_TAB, data[offset:]))

def udp_handler(data):
    """ Process UDP segment """
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    print(f"{TAB_1}UDP Segment:\n{TAB_2}Source Port: {src_port}, Destination Port: {dest_port}, Length: {size}")
    print(format_data(DATA_TAB, data[8:]))

def format_data(prefix, string, size=80):
    """ Format multi-line data display """
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

if __name__ == "__main__":
    main()
