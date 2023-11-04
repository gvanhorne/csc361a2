import sys
from pcap_header import PCAPHeader
from packet_header import PacketHeader
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
            connection.update_state(packet, packet_header.timestamp)
            connection.packets.append(packet)
            break
    else:
        # No matching connection, so append to the list of collections
        packet_connection.connection_src = packet.ip_header.src_ip
        packet_connection.connection_dst = packet.ip_header.dst_ip
        packet_connection.update_state(packet, packet_header.timestamp)
        packet_connection.packets.append(packet)
        connections.append(packet_connection)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 tcp_tracer.py <tracefile>.cap")
        sys.exit(1)
    total_num_packets = 0
    connections = []
    tracefile = sys.argv[1]
    orig_time = 0
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
                    if orig_time == 0:
                        packet_header.timestamp_set(packet_header_bytes[0:4], packet_header_bytes[4:8], orig_time)
                        orig_time = packet_header.timestamp
                        packet_header.timestamp_set(packet_header_bytes[0:4], packet_header_bytes[4:8], orig_time)
                    else:
                        packet_header.timestamp_set(packet_header_bytes[0:4], packet_header_bytes[4:8], orig_time)
                    packet.timestamp = packet_header.timestamp
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
        num_complete_connections = 0
        num_reset_connections = 0
        num_open_connections = 0
        min_time_duration = float("inf")
        max_time_duration = 0
        sum_time_duration = 0
        min_rtt = float("inf")
        max_rtt = 0
        min_packets = float("inf")
        max_packets = 0

        for connection in connections:
            print(f"Connection {i}:")
            print(f"Source Address: {connection.src_ip}")
            print(f"Destination Address: {connection.dst_ip}")
            print(f"Source Port: {connection.src_port}")
            print(f"Destination Port: {connection.dst_port}")
            print(f"Status: {connection.state}")
            if (connection.num_rst >= 1):
                num_reset_connections += 1
            if (connection.num_fin < 1):
                num_open_connections += 1
            if (connection.num_syn >= 1 and connection.num_fin >= 1):
                num_complete_connections += 1
                duration = round(connection.end_time - connection.start_time, 6)
                if (connection.get_min_rtt() < min_rtt):
                    min_rtt = round(connection.min_RTT, 6)
                elif (connection.max_RTT > max_rtt):
                    max_rtt = round(connection.max_RTT, 6)
                if (duration < min_time_duration):
                    min_time_duration = duration
                if (duration > max_time_duration):
                    max_time_duration = duration
                sum_time_duration += duration
                if (connection.num_packets_to_src + connection.num_packets_to_dst < min_packets):
                    min_packets = connection.num_packets_to_src + connection.num_packets_to_dst
                elif (connection.num_packets_to_src + connection.num_packets_to_dst > max_packets):
                    max_packets = connection.num_packets_to_src + connection.num_packets_to_dst
                print(f"Start Time: {connection.start_time}")
                print(f"End Time: {connection.end_time}")
                print(f"Duration: {duration}")
                print(f"Number of packets sent from Source to Destination: {connection.num_packets_to_dst}")
                print(f"Number of packets sent from Destination to Source: {connection.num_packets_to_src}")
                print(f"Total number of packets: {connection.num_packets_to_dst + connection.num_packets_to_src}")
                print(f"Number of data bytes sent from Source to Destination: {connection.num_bytes_to_dst}")
                print(f"Number of data bytes sent from Destination to Source: {connection.num_bytes_to_src}")
                print(f"Total number of data bytes: {connection.total_num_bytes}")
            print("END")
            i += 1
            if i < len(connections) + 1:
                print("++++++++++++++++++++++++++++++++")
        print("________________________________________________")
        print("C) General\n")
        print(f"Total number of complete TCP connections: {num_complete_connections}")
        print(f"Number of reset TCP connections: {num_reset_connections}")
        print(f"Number of TCP connections that were still open when the trace capture ended: {num_open_connections}")
        print("________________________________________________")
        print("D) Complete TCP Connections\n")
        print(f"Minimum time duration: {min_time_duration}")
        print(f"Mean time duration: {round(sum_time_duration/num_complete_connections, 6)}")
        print(f"Maximum time duration: {max_time_duration}\n")

        print(f"Minimum RTT value: {min_rtt}")
        print(f"Maximum RTT value: {max_rtt}\n")

        print(f"Minimum of packets: {min_packets}")
        print(f"Maximum number of packets: {max_packets}")