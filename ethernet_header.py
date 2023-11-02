import struct

class EthernetHeader:
    def __init__(self, dest_mac, source_mac, eth_type):
        self.dest_mac = dest_mac
        self.source_mac = source_mac
        self.eth_type = eth_type

    def __str__(self):
        return f"Destination MAC Address: {self.dest_mac.hex(':')}\n" \
               f"Source MAC Address: {self.source_mac.hex(':')}\n" \
               f"Ethernet Type: {hex(self.eth_type)}"

    @classmethod
    def from_bytes(cls, bytes):
        dest_mac, source_mac, eth_type = struct.unpack("!6s6sH", bytes)
        return cls(dest_mac, source_mac, eth_type)
