import pyshark

capture = pyshark.FileCapture('./PicoCTF/Misc/shark on wire 2/capture.pcap', display_filter='udp.port == 22')

data = []
for pkt in capture:
    if pkt.udp.port != '5000':
        data.append(chr(int(pkt.udp.port[1:])))
print("".join(data))