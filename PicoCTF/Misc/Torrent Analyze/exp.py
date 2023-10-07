import pyshark

capture = pyshark.FileCapture('PicoCTF/Misc/Torrent Analyze/torrent.pcap', display_filter='bt-dht contains "info_hash"')

info_hashs = []
for pkt in capture:
    info_hash = pkt.layers[3].get_field_by_showname('info_hash').showname_value
    if info_hash not in info_hashs:
        print(info_hash)
        info_hashs.append(info_hash)
    