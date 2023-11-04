class Connection:
  def __init__(self, src_ip, src_port, dst_ip, dst_port):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.packets = []
        self.state = 'S0F0'
        self.num_syn = 0
        self.num_fin = 0
        self.num_rst = 0
        self.start_time = 0
        self.end_time = 0
        self.orig_time = 0
        self.connection_src = None
        self.connection_dst = None
        self.num_packets_to_dst = 0
        self.num_packets_to_src = 0
        self.num_bytes_to_dst = 0
        self.num_bytes_to_src = 0
        self.total_num_bytes = 0
        self.min_RTT = float("inf")
        self.max_RTT = 0
        self.window_sizes = []

  def __eq__(self, other):
    if isinstance(other, Connection):
      return (
          (self.src_ip == other.src_ip and self.src_port == other.src_port and
            self.dst_ip == other.dst_ip and self.dst_port == other.dst_port) or
          (self.src_ip == other.dst_ip and self.src_port == other.dst_port and
            self.dst_ip == other.src_ip and self.dst_port == other.src_port)
      )
    return False

  def get_window_sizes(self):
    window_sizes = []
    for packet in self.packets:
      window_sizes.append(packet.tcp_header.window_size)
    self.window_sizes = window_sizes
    return self.window_sizes
  
  def add_packet(self, packet):
    self.packets.append(packet)

  def update_state(self, packet, timestamp):
    self.num_syn += packet.tcp_header.flags["SYN"]
    self.num_fin += packet.tcp_header.flags["FIN"]
    self.num_rst += packet.tcp_header.flags["RST"]
    if self.num_rst > 0:
      self.state = f"S{self.num_syn}F{self.num_fin}/R"
    else:
      self.state = f"S{self.num_syn}F{self.num_fin}"
    if self.num_syn == 1:
      self.start_time = timestamp
    if packet.tcp_header.flags["FIN"] == 1:
      self.end_time = timestamp
    if packet.ip_header.dst_ip == self.connection_dst:
      self.num_packets_to_dst += 1
      self.num_bytes_to_dst += packet.data_bytes
    elif packet.ip_header.dst_ip == self.connection_src:
      self.num_packets_to_src += 1
      self.num_bytes_to_src += packet.data_bytes
    self.total_num_bytes += packet.data_bytes

  def get_min_rtt(self):
    for i, packet in enumerate(self.packets):
      if (
          packet.ip_header.dst_ip == self.connection_dst
          and packet.tcp_header.flags["RST"] == 0
          and packet.tcp_header.flags != {"ACK": 1, "SYN": 0, "FIN": 0, "RST": 0}
      ):
        expected_ack = packet.tcp_header.seq_num + 1
        for j, other_packet in enumerate(self.packets):
            if i != j:
                if (
                    other_packet.tcp_header.ack_num == expected_ack
                ):
                  diff = abs((other_packet.timestamp - packet.timestamp))
                  if diff < self.min_RTT:
                    self.min_RTT = diff
                  elif diff > self.max_RTT:
                    self.max_RTT = diff
    return self.min_RTT
