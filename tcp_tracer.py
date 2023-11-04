import sys
from pcap_header import PCAPHeader
from packet_header import PacketHeader
from packet import Packet
from connection import Connection

def analyze_connections(connections):
    """
    Analyze a list of connections and print connection details and statistics.

    Args:
        connections (list): List of Connection objects to be analyzed.

    Returns:
        None
    """
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
    sum_packets = 0
    window_sizes = []
    rtts = []

    for i, connection in enumerate(connections, start=1):
        if connection.num_rst >= 1:
            num_reset_connections += 1
        if connection.num_fin < 1:
            num_open_connections += 1
        if connection.num_syn >= 1 and connection.num_fin >= 1:
            num_complete_connections += 1
            duration = round(connection.end_time - connection.start_time, 6)
            min_time_duration, max_time_duration, sum_time_duration = update_duration_stats(
                duration, min_time_duration, max_time_duration, sum_time_duration
            )
            min_rtt, max_rtt, rtts = update_rtt_stats(connection, min_rtt, max_rtt, rtts)
            min_packets, max_packets, sum_packets = update_packet_stats(
                connection, min_packets, max_packets, sum_packets
            )
            window_sizes.extend(connection.get_window_sizes())
            print_connection_details(i, connection, True)
        else:
            print_connection_details(i, connection, False)
        
    print_general_stats(num_complete_connections, num_reset_connections, num_open_connections)
    print_complete_tcp_connection_stats(num_complete_connections, min_time_duration, max_time_duration, sum_time_duration,
                                        min_rtt, max_rtt, rtts, min_packets, max_packets, sum_packets, window_sizes)

def print_connection_details(i, connection, is_complete_connection):
    """
    Print details of a connection.

    Args:
        i (int): Index of the connection.
        connection (Connection): The Connection object to be printed.
        is_complete_connection (bool): True if the connection is complete, False otherwise.

    Returns:
        None
    """
    print(f"Connection {i}:")
    print(f"Source Address: {connection.src_ip}")
    print(f"Destination Address: {connection.dst_ip}")
    print(f"Source Port: {connection.src_port}")
    print(f"Destination Port: {connection.dst_port}")
    print(f"Status: {connection.state}")
    if is_complete_connection:
        print("Start Time:", connection.start_time)
        print("End Time:", connection.end_time)
        print("Duration:", round(connection.end_time - connection.start_time, 6))
        print(f"Number of packets sent from Source to Destination: {connection.num_packets_to_dst}")
        print(f"Number of packets sent from Destination to Source: {connection.num_packets_to_src}")
        print(f"Total number of packets: {connection.num_packets_to_dst + connection.num_packets_to_src}")
        print(f"Number of data bytes sent from Source to Destination: {connection.num_bytes_to_dst}")
        print(f"Number of data bytes sent from Destination to Source: {connection.num_bytes_to_src}")
        print(f"Total number of data bytes: {connection.total_num_bytes}")
    print("END")
    if (i < len(connections)):
        print("++++++++++++++++++++++++++++++++")

def update_duration_stats(duration, min_duration, max_duration, sum_duration):
    """
    Update duration statistics.

    Args:
        duration (float): Duration value to be updated.
        min_duration (float): Minimum duration value.
        max_duration (float): Maximum duration value.
        sum_duration (float): Sum of duration values.

    Returns:
        tuple: Updated min_duration, max_duration, and sum_duration.
    """
    new_min_duration = min(min_duration, duration)
    new_max_duration = max(max_duration, duration)
    new_sum_duration = sum_duration + duration
    return new_min_duration, new_max_duration, new_sum_duration


def update_rtt_stats(connection, min_rtt, max_rtt, rtts):
    """
    Update RTT (Round-Trip Time) statistics.

    Args:
        connection (Connection): The Connection object to get RTT information from.
        min_rtt (float): Minimum RTT value.
        max_rtt (float): Maximum RTT value.
        rtts (list): List of RTT values.

    Returns:
        tuple: Updated min_rtt, max_rtt, and rtts.
    """
    new_min_rtt = min(min_rtt, connection.get_min_rtt())
    new_max_rtt = max(max_rtt, connection.max_RTT)
    new_rtts = rtts + connection.get_rtts()
    return new_min_rtt, new_max_rtt, new_rtts

def update_packet_stats(connection, min_packets, max_packets, sum_packets):
    """
    Update packet statistics.

    Args:
        connection (Connection): The Connection object to get packet information from.
        min_packets (int): Minimum number of packets.
        max_packets (int): Maximum number of packets.
        sum_packets (int): Sum of packet counts.

    Returns:
        tuple: Updated min_packets, max_packets, and sum_packets.
    """
    num_packets = connection.num_packets_to_src + connection.num_packets_to_dst
    new_min_packets = min(min_packets, num_packets)
    new_max_packets = max(max_packets, num_packets)
    new_sum_packets = sum_packets + num_packets
    return new_min_packets, new_max_packets, new_sum_packets

def print_general_stats(num_complete_connections, num_reset_connections, num_open_connections):
    """
    Print general statistics.

    Args:
        num_complete_connections (int): Number of complete TCP connections.
        num_reset_connections (int): Number of reset TCP connections.
        num_open_connections (int): Number of TCP connections that were still open when the trace capture ended.

    Returns:
        None
    """
    print("________________________________________________\n")
    print("C) General\n")
    print(f"Total number of complete TCP connections: {num_complete_connections}")
    print(f"Number of reset TCP connections: {num_reset_connections}")
    print(f"Number of TCP connections that were still open when the trace capture ended: {num_open_connections}")

def print_complete_tcp_connection_stats(num_complete_connections, min_duration, max_duration, sum_duration,
                                        min_rtt, max_rtt, rtts, min_packets, max_packets, sum_packets, window_sizes):
    """
    Print statistics for complete TCP connections.

    Args:
        num_complete_connections (int): Number of complete TCP connections.
        min_duration (float): Minimum duration value.
        max_duration (float): Maximum duration value.
        sum_duration (float): Sum of duration values.
        min_rtt (float): Minimum RTT value.
        max_rtt (float): Maximum RTT value.
        rtts (list): List of RTT values.
        min_packets (int): Minimum number of packets.
        max_packets (int): Maximum number of packets.
        sum_packets (int): Sum of packet counts.
        window_sizes (list): List of window sizes.

    Returns:
        None
    """
    print("________________________________________________\n")
    print("D) Complete TCP Connections\n")
    print(f"Minimum time duration: {min_duration}")
    print(f"Mean time duration: {round(sum_duration / num_complete_connections, 6)}")
    print(f"Maximum time duration: {max_duration}\n")
    print(f"Minimum RTT value: {round(min_rtt, 6)}")
    print(f"Mean RTT value: {round(sum(rtts) / len(rtts), 6)}")
    print(f"Maximum RTT value: {round(max_rtt, 6)}\n")
    print(f"Minimum of packets: {min_packets}")
    print(f"Mean number of packets: {round(sum_packets / num_complete_connections, 6)}")
    print(f"Maximum number of packets: {max_packets}\n")
    print(f"Minimum received window size: {min(window_sizes)}")
    print(f"Mean received window size: {round(sum(window_sizes) / len(window_sizes), 6)}")
    print(f"Maximum received window size: {max(window_sizes)}")

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

    existing_connection = next((conn for conn in connections if conn == packet_connection), None)
    if existing_connection:
        existing_connection.update_state(packet, packet_header.timestamp)
        existing_connection.add_packet(packet)
    else:
        # No matching connection, so append to the list of collections
        packet_connection.connection_src = packet.ip_header.src_ip
        packet_connection.connection_dst = packet.ip_header.dst_ip
        packet_connection.update_state(packet, packet_header.timestamp)
        packet_connection.add_packet(packet)
        connections.append(packet_connection)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 tcp_tracer.py <tracefile>.cap")
        sys.exit(1)
    connections = []
    tracefile = sys.argv[1]
    orig_time = 0
    try:
        with open(tracefile, 'rb') as f:
            global_header_bytes = f.read(24)
            global_header = PCAPHeader.from_bytes(global_header_bytes)

            # Process individual packets
            while True:
                packet_header_bytes = f.read(16)

                if not packet_header_bytes:
                    break
                else:
                    packet_header = PacketHeader.from_bytes(packet_header_bytes, hex(global_header.magic_number))

                    # Read the packet data based on the "incl_len" from the packet header
                    packet_bytes = f.read(packet_header.incl_len)

                    # Create a Packet instance by parsing the packet data
                    packet = Packet.from_bytes(packet_bytes)

                    # Handle the timestamp for the packet
                    if orig_time == 0:
                        packet_header.timestamp_set(packet_header_bytes[0:4], packet_header_bytes[4:8], orig_time)
                        orig_time = packet_header.timestamp
                        packet_header.timestamp_set(packet_header_bytes[0:4], packet_header_bytes[4:8], orig_time)
                    else:
                        packet_header.timestamp_set(packet_header_bytes[0:4], packet_header_bytes[4:8], orig_time)

                    # Set the packet's timestamp and add the connection to the list
                    packet.timestamp = packet_header.timestamp
                    add_connection(packet, connections)
    except IOError:
        print("Could not read file:", tracefile)
    finally:
        f.close()
        print(f"A) Total number of connections: {len(connections)}")
        print('________________________________________________\n')
        print("B) Connections details\n")
        analyze_connections(connections)