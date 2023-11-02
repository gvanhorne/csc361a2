import struct
import sys
from pcap_header import PCAPHeader
from packet_header import PacketHeader
from ip_header import IPHeader
from tcp_header import TCPHeader

class Packet():
    #pcap_hd_info = None
    IP_header = None
    TCPHeader = None
    timestamp = 0
    packet_No = 0
    RTT_value = 0
    RTT_flag = False
    buffer = None
    
    
    def __init__(self):
        self.IP_header = IPHeader()
        self.TCPHeader = TCPHeader()
        #self.pcap_hd_info = pcap_ph_info()
        self.timestamp = 0
        self.packet_No =0
        self.RTT_value = 0.0
        self.RTT_flag = False
        self.buffer = None
        
    def timestamp_set(self,buffer1,buffer2,orig_time):
        seconds = struct.unpack('I',buffer1)[0]
        microseconds = struct.unpack('<I',buffer2)[0]
        self.timestamp = round(seconds+microseconds*0.000001-orig_time,6)
        #print(self.timestamp,self.packet_No)
    def packet_No_set(self,number):
        self.packet_No = number
        #print(self.packet_No)
        
    def get_RTT_value(self,p):
        rtt = p.timestamp-self.timestamp
        self.RTT_value = round(rtt,8)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 tcp_tracer.py <tracefile>.cap")
        sys.exit(1)

    tracefile = sys.argv[1]
    try:
        with open(tracefile, 'rb') as f:
            global_header_bytes = f.read(24)
            global_header = PCAPHeader.from_bytes(global_header_bytes)
            ## Check thiszone...
            packet_header_bytes = f.read(16)
            packet_header = PacketHeader.from_bytes(packet_header_bytes, hex(global_header.magic_number))
            print(packet_header)
            # packet_header = parse_packet_header(packet_header1)
            ## check incl_len for len of packet, and ts_sec for the time
            ## packet_data1 = f.read(incl_len)
            ## continue above to split every packet
    except IOError:
        print("Could not read file:", tracefile)
    finally:
        f.close()