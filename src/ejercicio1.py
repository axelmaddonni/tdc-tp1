from scapy.all import * 
def monitor_callback(pkt):
  print printpkt.show()

if __name__ == 'main':
  sniff(iface="eth0",  prn=lambda x: x.summary())
