#!/usr/bin/env python2
import sys
import math
from scapy.all import *

fuente = {}
cantidad = 0

def packet_callback(pkt):
  global fuente, cantidad
  if ARP in pkt and pkt[ARP].op == 2:  # x.op == 2 sii x es un is at
    s = pkt.src
    if s in fuente:
      fuente[s] += 1
    else:
      fuente[s] = 1
    cantidad+=1

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


for a in fuente:
  fuente[a] = float(fuente[a]) / cantidad

entropia = sum([-math.log(fuente[a], 2)*fuente[a] for a in fuente])
print 'Fuente:', fuente
print 'Entropia:', entropia

for a in fuente: # chequeamos si es distinguido
  if -math.log(fuente[a], 2) <= entropia:
    print 'Nodo distinguido:', a
