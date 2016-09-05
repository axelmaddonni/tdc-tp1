# tdc-tp1
tdc-tp1 2c 2016

## Fecha de entrega
19-09-2016

## Como darle capabilities a python (para leer paquetes)

    sudo setcap cap_net_raw=eip /usr/bin/python2.7

Cambien python2.7 por como se llame su binario de python.

## Cómo escuchar paquetes con Wireshark.

Es importante que esten conectados a internet por la interfaz que van a usar.
Por ejemplo, si van a escuchar una red cableada, *apaguen el wifi* y si van a escuchar una red wi-fi, *desconecten cualquier cable ethernet echufado a la pc*. A continuación, conectense a la red que quieran analizar y ponganse en modo monitor. Para eso primero averiguen la interfaz.

    ifconfig

Busquen ahí dónde aparece su interfaz. Nombre clásico de ethernet: eth1/eno1, nombre clásico de wifi: wlan0/wlp3s0. Luego, activen modo promiscuo:

    sudo ifconfig <interfaz> promisc

Después corran el wireshark con esa interfaz. Dejenlo corriendo un rato largo (mínimo 10 minutos, pero habian dicho que horas es lo mejor). Después guarden el resultado con formato Wireshark/tcpdump/.

Capaz les convenga guardar solo los paquetes ARP (escribiendo "arp" en la barra de filtrado, y despues "File -> Export specified packages").

Después corran las herramientas para analizar el resultado.

