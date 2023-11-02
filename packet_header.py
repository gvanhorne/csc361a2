import struct

class PacketHeader:
    """
    Represents a packet header.

    Attributes:
    - ts_sec (int): The timestamp in seconds.
    - ts_usec (int): The timestamp in microseconds.
    - incl_len (int): The number of bytes captured and included in the packet.
    - orig_len (int): The original length of the packet.

    Methods:
    - __init__(ts_sec, ts_usec, incl_len, orig_len): Initializes a PacketHeader object with the specified values.
    - __str__(): Returns a string representation of the PacketHeader object.
    - from_bytes(cls, header_bytes): Create a PacketHeader object from a byte sequence.
      - Parameters:
        - cls (class): The class to create an instance of.
        - header_bytes (bytes): The byte sequence containing packet header data.
      - Returns:
        - PacketHeader: A PacketHeader object representing the parsed header data.
      - Raises:
        - ValueError: If the length of header_bytes is not 16 (invalid header length).
    """
    def __init__(self, ts_sec, ts_usec, incl_len, orig_len):
        self.ts_sec = ts_sec
        self.ts_usec = ts_usec
        self.incl_len = incl_len
        self.orig_len = orig_len

    def __str__(self):
        """
        Returns a string representation of the PacketHeader object.
        """
        return (
            f"Timestamp (seconds): {self.ts_sec}\n"
            f"Timestamp (microseconds): {self.ts_usec}\n"
            f"Included Length: {self.incl_len}\n"
            f"Original Length: {self.orig_len}"
        )

    @classmethod
    def from_bytes(cls, header_bytes):
        """
        Create a PacketHeader object from a byte sequence.

        Parameters:
        - cls (class): The class to create an instance of.
        - header_bytes (bytes): The byte sequence containing packet header data.

        Returns:
        - PacketHeader: A PacketHeader object representing the parsed header data.

        Raises:
        - ValueError: If the length of header_bytes is not 16 (invalid header length).
        """
        if len(header_bytes) != 16:
            raise ValueError("Invalid packet header length")
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack("<IIII", header_bytes)
        return cls(ts_sec, ts_usec, incl_len, orig_len)