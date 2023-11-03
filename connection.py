class Connection:
  packets = []
  state = 'S0F0'
  num_syn = 0
  num_fin = 0
  num_rst = 0
  start_time = 0
  end_time = 0
  orig_time = 0

  def __init__(self, src_ip, src_port, dst_ip, dst_port):
    self.src_ip = src_ip
    self.src_port = src_port
    self.dst_ip = dst_ip
    self.dst_port = dst_port

  def __eq__(self, other):
    if isinstance(other, Connection):
      return (
          (self.src_ip == other.src_ip and self.src_port == other.src_port and
            self.dst_ip == other.dst_ip and self.dst_port == other.dst_port) or
          (self.src_ip == other.dst_ip and self.src_port == other.dst_port and
            self.dst_ip == other.src_ip and self.dst_port == other.src_port)
      )
    return False

  def update_state(self, tcp_header, timestamp):
    self.num_syn += tcp_header.flags["SYN"]
    self.num_fin += tcp_header.flags["FIN"]
    self.num_rst += tcp_header.flags["RST"]
    if self.num_rst > 0:
      self.state = f"S{self.num_syn}F{self.num_fin}/R"
    else:
      self.state = f"S{self.num_syn}F{self.num_fin}"
    if self.num_syn == 1:
      self.start_time = timestamp
    if tcp_header.flags["FIN"] == 1:
      self.end_time = timestamp

