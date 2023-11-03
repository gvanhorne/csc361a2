import struct
import sys
from pcap_header import PCAPHeader
from packet_header import PacketHeader
from ip_header import IPHeader
from tcp_header import TCPHeader
from packet import Packet

def add_connection(packet, connections):
    """
    Adds a connection tuple to the connections set if it and the reverse connection are not already present.

    Args:
        packet: The packet containing connection information.
        connections: The set of connections to which the new connection should be added.

    Returns:
        None
    """
    connection = (
        packet.ip_header.src_ip,
        packet.tcp_header.src_port,
        packet.ip_header.dst_ip,
        packet.tcp_header.dst_port
    )

    reverse_connection = (
        packet.ip_header.dst_ip,
        packet.tcp_header.dst_port,
        packet.ip_header.src_ip,
        packet.tcp_header.src_port
        )
    if (reverse_connection not in connections and connection not in connections):
        connections.append(connection)

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
            ## check incl_len for len of packet, and ts_sec for the time
            ## packet_data1 = f.read(incl_len)
            ## continue above to split every packet
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
            print(f"Source Address: {connection[0]}")
            print(f"Destination Address: {connection[2]}")
            print(f"Source Port: {connection[1]}")
            print(f"Destination Port: {connection[3]}")
            print("END")
            print("++++++++++++++++++++++++++++++++")
            i += 1