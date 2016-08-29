import sys
import math
from scapy.all import * 
def monitor_callback(pkt):
  print printpkt.show()


s_broadcast = 0
s_unicast = 0
total = 0

fuente = {}
cantidad = 0

if len(sys.argv) > 1:
	a=rdpcap(sys.argv[1])
	for x in a:
		if ARP in x and x.op == 0:  # x.op == 0 sii x es un is at
			s = x.src
			if s in fuente:
				fuente[s] += 1
			else:
				fuente[s] = 1
			cantidad+=1

for a in fuente:
	fuente[a] = float(fuente[a]) / cantidad

entropia = sum([-math.log(fuente[a], 2)*fuente[a] for a in fuente])

for a in fuente: # chequeamos si es distinguido
	if -math.log(fuente[a], 2) < entropia:
		print a
