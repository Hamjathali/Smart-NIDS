from scapy.all import sniff, wrpcap

# Capture 50 packets
packets = sniff(count=50)

# Save them to a file
wrpcap("sample.pcap", packets)

print("sample.pcap created successfully!")
