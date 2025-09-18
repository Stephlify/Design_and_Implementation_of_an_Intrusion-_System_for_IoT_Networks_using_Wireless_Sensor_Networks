# near top of 1_PacketCapture.py or in main
from scapy.all import sniff, conf, get_if_list

# ensure pcap backend on Windows
try:
    conf.use_pcap = True
except Exception:
    pass

class PacketCapture:
    def __init__(self):
        self.packet_queue = queue.Queue()
        self.stop_capture = threading.Event()

    def packet_callback(self, packet):
        from scapy.layers.inet import IP, TCP
        if IP in packet and TCP in packet:
            self.packet_queue.put(packet)

    def start_capture(self, interface=None, bpf_filter="tcp"):
        # pick default interface if none specified
        if not interface:
            # prints available interfaces; choose one and pass to constructor
            print("Available interfaces:", get_if_list())
            interface = get_if_list()[0]  # or ask user to provide one
        def capture_thread():
            sniff(iface=interface, filter=bpf_filter, prn=self.packet_callback,
                  store=0, stop_filter=lambda _: self.stop_capture.is_set())
        self.capture_thread = threading.Thread(target=capture_thread, daemon=True)
        self.capture_thread.start()
