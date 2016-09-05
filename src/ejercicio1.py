import sys
from scapy.all import *

s_broadcast = 0
s_unicast = 0
total = 0

def packet_callback(pkt):
  global s_broadcast, s_unicast, total
  if pkt.dst == "ff:ff:ff:ff:ff:ff":
    s_broadcast += 1
  else:
    s_unicast += 1
  total += 1
  print "P(s_broadcast) =", round(float(s_broadcast) / total, 4),\
        "\tP(s_unicast) =", round(float(s_unicast) / total, 4), \
        "\t[", s_unicast, ",", s_broadcast, ",", total, "]"

try:
  if len(sys.argv) > 1:
    a=rdpcap(sys.argv[1])
    for x in a:
      packet_callback(x)
  else:
    print "Si deseas parar, apreta Ctrl-C."
    sniff(prn=packet_callback, store=0)
except KeyboardInterrupt:
    print "Terminando..."


