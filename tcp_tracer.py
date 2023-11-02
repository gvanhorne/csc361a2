import struct
import sys
from pcap_header import PCAPHeader
from packet_header import PacketHeader
from ip_header import IPHeader
from tcp_header import TCPHeader
from packet import Packet

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
            while total_num_packets == 0:
                packet_header_bytes = f.read(16)
                if not packet_header_bytes:
                    break
                else:
                    packet_header = PacketHeader.from_bytes(packet_header_bytes, hex(global_header.magic_number))
                    packet_bytes = f.read(packet_header.incl_len)
                    packet = Packet.from_bytes(packet_bytes)
                    total_num_packets += 1
            ## check incl_len for len of packet, and ts_sec for the time
            ## packet_data1 = f.read(incl_len)
            ## continue above to split every packet
    except IOError:
        print("Could not read file:", tracefile)
    finally:
        f.close()
        print(total_num_packets)