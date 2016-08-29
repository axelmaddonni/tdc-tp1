import sys
from scapy.all import * 
def monitor_callback(pkt):
  print printpkt.show()


s_broadcast = 0
s_unicast = 0
total = 0

if len(sys.argv) > 1:
	a=rdpcap(sys.argv[1])
	for x in a:
		if x.dst == "ff:ff:ff:ff:ff:ff":
			s_broadcast += 1
		else:
			s_unicast += 1
		total += 1

		print "P(s_broadcast) =", round(float(s_broadcast) / total, 4),\
		      "\tP(s_unicast) =", round(float(s_unicast) / total, 4)
