import struct
import sys
from pcap_header import PCAPHeader
from packet_header import PacketHeader
from ip_header import IPHeader
from tcp_header import TCPHeader
from packet import Packet
from connection import Connection

def add_connection(packet, connections):
    """
    Adds a connection tuple to the connections set if it and the reverse connection are not already present.

    Args:
        packet: The packet containing connection information.
        connections: The set of connections to which the new connection should be added.

    Returns:
        None
    """
    packet_connection = Connection(
        packet.ip_header.src_ip,
        packet.tcp_header.src_port,
        packet.ip_header.dst_ip,
        packet.tcp_header.dst_port
    )

    for connection in connections:
        if connection == packet_connection:
            connection.update_state(packet.tcp_header)
            connection.packets.append(packet)
            break
    else:
        packet_connection.update_state(packet.tcp_header)
        packet_connection.packets.append(packet)
        connections.append(packet_connection)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 tcp_tracer.py <tracefile>.cap")
        sys.exit(1)
    total_num_packets = 0
    connections = []
    tracefile = sys.argv[1]
    try:
        with open(tracefile, 'rb') as f:
            global_header_bytes = f.read(24)
            global_header = PCAPHeader.from_bytes(global_header_bytes)
            while True:
                packet_header_bytes = f.read(16)
                if not packet_header_bytes:
                    break
                else:
                    packet_header = PacketHeader.from_bytes(packet_header_bytes, hex(global_header.magic_number))
                    packet_bytes = f.read(packet_header.incl_len)
                    packet = Packet.from_bytes(packet_bytes)
                    add_connection(packet, connections)
                    total_num_packets += 1
    except IOError:
        print("Could not read file:", tracefile)
    finally:
        f.close()
        # print(total_num_packets)
        print(f"A) Total number of connections: {len(connections)}")
        print('________________________________________________\n')
        print("B) Connections details\n")
        i = 1
        for connection in connections:
            print(f"Connection {i}:")
            print(f"Source Address: {connection.src_ip}")
            print(f"Destination Address: {connection.dst_ip}")
            print(f"Source Port: {connection.src_port}")
            print(f"Destination Port: {connection.dst_port}")
            print(f"Status: {connection.state}")
            print("END")
            print("++++++++++++++++++++++++++++++++")
            i += 1