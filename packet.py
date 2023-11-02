import struct
from ip_header import IPHeader
from tcp_header import TCPHeader
from ethernet_header import EthernetHeader

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
    
    @classmethod
    def from_bytes(cls, packet_bytes):
        ethernet_bytes = packet_bytes[:14]
        ethernet_header = EthernetHeader.from_bytes(ethernet_bytes)