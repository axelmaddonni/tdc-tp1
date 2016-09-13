'''
Como usar:
    python src/hacer_graficos.py capturas/captura.pcap
O en su defecto:
    python2 src/hacer_graficos.py capturas/captura.pcap
'''

import sys
import matplotlib.pyplot as plt
import math
from scapy.all import *
import numpy as np
import pprint

pp = pprint.PrettyPrinter(indent=4)

try:
    from graphviz import Digraph
except:
    print 'Instala graphviz!!!!'
    print '    pip install --user graphviz'
    print 'Si eso no te anda...'
    print '    pip2 install --user graphviz'
    exit(1)

s_broadcast = 0
s_unicast = 0
total = 0

def grafico1(s_broadcast, s_unicast):
    total = s_broadcast + s_unicast
    p_broadcast = float(s_broadcast) / total
    p_unicast = float(s_unicast) / total
    i_broadcast = -math.log(float(s_broadcast) / total, 2)
    i_unicast = -math.log(float(s_unicast) / total, 2)
    entropia = p_broadcast * i_broadcast + p_unicast * i_unicast
    fig, ax = plt.subplots()
    bar1 = ax.bar([0, 1], [i_broadcast, i_unicast], 0.8, color='#517a8b')
    entrop=ax.axhline(y=entropia, label='Entropia', color='#0c1915', ls='--')
    entropm=ax.axhline(y=1.0, label='Entropia Maxima', color='#fcd68b', ls='--')
    plt.legend(handles=[entrop, entropm])
    ax.set_xticks([0.4, 1.4])
    ax.set_xticklabels(['s_broadcast', 's_unicast'])
    # #0c1915
    #  #ffe683
    ax.set_yscale("log")
    ax.set_title("Informacion de los simbolos de la fuente S")
    plt.tight_layout()
    plt.savefig('grafico1.pdf')


def grafico2(pkts_arp):
    dot = Digraph(comment='Red de mensajes ARP')
    actores = []
    edges = []
    for pkt in pkts_arp:
        if pkt[ARP].op == 1: # x.op == 2 sii x es un is at
            actores.append(pkt[ARP].psrc)
            actores.append(pkt[ARP].pdst)
            edges.append((pkt[ARP].psrc, pkt[ARP].pdst))
    edges_ = set(edges)
    for a in actores:
        dot.node(a.replace(':', ''), a)
    for e in edges_:
        dot.edge(e[0].replace(':', ''), e[1].replace(':', ''))
    dot.render('grafico2', view=True)


def grafico3(pkts_arp):
    ###### GRAFICO 3
    fuente = {}
    cantidad = 0
    for pkt in pkts_arp:
        if pkt[ARP].op == 1:
            s = pkt[ARP].pdst
            if s in fuente:
                fuente[s] += 1
            else:
                fuente[s] = 1
            cantidad+=1

    for a in fuente:
        fuente[a] = float(fuente[a]) / cantidad

    pp.pprint(fuente)

    entropia = sum([-math.log(fuente[a], 2)*fuente[a] for a in fuente])
    informacion = {}
    for a in fuente:
        informacion[a] = -math.log(fuente[a], 2)

    #informacion = {k : v for k, v in informacion.iteritems() if v < entropia*2.3}


    l = [(informacion[a], a) for a in informacion]
    ind = range(len(l))
    pp.pprint(l)
    l.sort()
    fig, ax = plt.subplots()
    ax.bar(ind, [x[0] for x in l], 0.8, color='#b5ae8f')
    entrop=plt.axhline(y=entropia, label='Entropia', color='#0c1915', ls='--')
    plt.legend(handles=[entrop])
    plt.xticks(list(map(lambda x: x+0.4, ind)),
            [x[1] for x in l],
            rotation='vertical')
    ax.set_title("Informacion de los simbolos de la fuente S1")
    plt.tight_layout()
    plt.savefig('grafico3.pdf')

    ###### GRAFICO 2
    dot = Digraph(comment='Red de mensajes ARP', engine='circo')
    dot.attr('graph', concentrate='true')
    actores = []
    edges = []
    for pkt in pkts_arp:
        if pkt[ARP].op == 1: # x.op == 2 sii x es un is at
            if pkt[ARP].psrc in informacion and pkt[ARP].pdst in informacion:
                actores.append(pkt[ARP].psrc)
                actores.append(pkt[ARP].pdst)
                if pkt[ARP].psrc != pkt[ARP].pdst:
                    edges.append((pkt[ARP].psrc, pkt[ARP].pdst))
    actores = set(actores)
    edges = set(edges)

    conectividad = {}
    for actor in actores:
        in_ = []
        out_ = []
        for edge in edges:
            if edge[0] == actor:
                out_.append(edge[1])
            if edge[1] == actor:
                in_.append(edge[0])
        conectividad[actor] = (in_, out_)

    sacar = {}
    nombrecitos = {}
    for elem in [sorted([x for x in actores if conectividad[x][0] == conectividad[y][0] and conectividad[x][1] == conectividad[y][1]]) for y in actores]:
        for i in elem[1:]:
            sacar[i] = elem[0]
        if len(elem) == 1:
            nombrecitos[elem[0]] = elem[0]
        else:
            nombrecitos[elem[0]] = elem[0]+' ['+str(len(elem))+']'

    edges_ = set(sorted(edges))
    for a in actores:
        if a not in sacar:
            if informacion[a] <= entropia:
                dot.node(a.replace(':', ''), nombrecitos[a], shape='box')
            else:
                dot.node(a.replace(':', ''), nombrecitos[a])
    for e in edges_:
        if e[0] not in sacar and e[1] not in sacar:
            if (e[1], e[0]) in edges:
                dot.edge(e[0].replace(':', ''), e[1].replace(':', ''), dir='both')
            else:
                dot.edge(e[0].replace(':', ''), e[1].replace(':', ''))
    dot.render('grafico2', view=True)




if len(sys.argv) > 1:
    a=rdpcap(sys.argv[1])
    pkts_arp = []
    s_broadcast = 0
    s_unicast = 0
    for x in a:
        if x.dst == "ff:ff:ff:ff:ff:ff":
            s_broadcast += 1
        else:
            s_unicast += 1
        if ARP in x:  # x.op == 2 sii x es un is at
            pkts_arp.append(x)
    grafico1(s_broadcast, s_unicast)
    #grafico2(pkts_arp)
    grafico3(pkts_arp)
