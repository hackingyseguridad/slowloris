### slowloris 

Ataque Slowloris de denegacion de servicio con peticiones web 

### Slowloris: entendimiento, detección y mitigación

---

### Slowloris

Slowloris es un ataque de **denegación de servicio (DoS)** de capa de aplicación (capa 7), descrito públicamente por primera vez por Robert "RSnake" Hansen en 2009. A diferencia de un DoS volumétrico (que satura el ancho de banda con tráfico masivo), Slowloris es un ataque de **bajo ancho de banda** que explota cómo algunos servidores web gestionan las conexiones HTTP concurrentes.

### 1.1 Principio de funcionamiento

Un servidor web tiene un número máximo de **hilos o procesos worker** disponibles para atender conexiones simultáneas (por ejemplo, `MaxRequestWorkers` en Apache). Cada conexión ocupa uno de esos workers **mientras el servidor espera a que la petición HTTP se complete**.

Slowloris abusa de esa espera:

1. Abre muchas conexiones TCP contra el servidor objetivo.
2. Envía una petición HTTP **incompleta** (por ejemplo, cabeceras sin la línea en blanco final que indica el fin de las cabeceras).
3. Cada cierto intervalo (antes de que salte el timeout), envía una cabecera adicional irrelevante para "mantener viva" la conexión, sin llegar nunca a completarla.
4. Repite esto con cientos o miles de conexiones simultáneas.

El resultado: todos los workers del servidor quedan **ocupados esperando indefinidamente**, sin poder atender a usuarios legítimos, aunque el consumo de ancho de banda y CPU sea mínimo.

### 1.2 Por qué es difícil de detectar con herramientas tradicionales

| Característica | DoS volumétrico clásico | Slowloris |
|---|---|---|
| Ancho de banda consumido | Alto | Muy bajo |
| Nº de paquetes por segundo | Alto | Muy bajo |
| Visibilidad en gráficas de tráfico (Mbps/pps) | Evidente | Prácticamente invisible |
| Recurso agotado | Red / CPU | Pool de conexiones / workers |
| Firma en IDS basado en volumen | Fácil de detectar | No suele disparar alarmas |
| Nº de IPs origen necesarias | Muchas (a menudo botnet) | Pocas, incluso una sola máquina |

### 1.3 Servidores afectados vs. no afectados

| Servidor / tecnología | Vulnerable por defecto | Motivo |
|---|---|---|
| Apache HTTPD (prefork/worker, sin `mod_reqtimeout`) | Sí | Modelo de workers limitado, sin timeout agresivo de cabeceras |
| Nginx | No (arquitectura por defecto es resistente) | Modelo de eventos asíncrono (event-driven), no bloquea un worker por conexión lenta |
| IIS | Parcialmente (versiones antiguas) | Mitigado desde IIS 7+ con límites de conexión |
| lighttpd | Parcialmente | Depende de configuración de timeouts |
| Servidores detrás de un reverse proxy/CDN robusto | No, si el proxy filtra | El proxy absorbe las conexiones lentas antes de llegar al backend |

---

### 2. Detección

### 2.1 Indicadores (IOCs) típicos

- Aumento sostenido de **conexiones TCP en estado `ESTABLISHED`** hacia el puerto 80/443 sin crecimiento proporcional de tráfico (Mbps).
- Muchas conexiones abiertas desde **pocas IPs origen**, con **duración anormalmente larga**.
- En los logs del servidor: peticiones que nunca terminan de registrarse (no aparece la línea de acceso completa porque la petición nunca se completó).
- Uso de `netstat`/`ss` mostrando decenas o cientos de conexiones en el mismo estado hacia el mismo puerto:

```bash
ss -ant | grep ':80' | awk '{print $1}' | sort | uniq -c
netstat -an | grep ':80' | grep ESTABLISHED | wc -l
```

- Métrica de **workers ocupados / disponibles** en el servidor web cercana al límite (`server-status` en Apache con `mod_status` habilitado).

### 2.2 Herramientas de monitorización recomendadas

| Herramienta | Qué aporta |
|---|---|
| `mod_status` (Apache) | Muestra en tiempo real el estado de cada worker (leyendo cabeceras, esperando, etc.) |
| Nginx `stub_status` / `ngx_http_status` | Conexiones activas, lectura/escritura/espera |
| Prometheus + Grafana (node_exporter, nginx-exporter) | Alertas sobre nº de conexiones y workers saturados |
| Fail2ban con filtro personalizado | Bloqueo automático de IPs con exceso de conexiones lentas |
| IDS/IPS (Suricata/Snort) con reglas de "slow HTTP" | Firma específica para patrones de cabeceras incompletas |

---

### 3. Mitigación

### 3.1 Apache HTTPD

El mecanismo principal es **`mod_reqtimeout`**, incluido desde Apache 2.2.15, que fuerza timeouts estrictos en la recepción de cabeceras y cuerpo de la petición.

```apache
# httpd.conf o virtualhost
<IfModule reqtimeout_module>
    RequestReadTimeout header=20-40,MinRate=500 body=20,MinRate=500
</IfModule>
```

- `header=20-40,MinRate=500`: da entre 20 y 40 segundos para completar las cabeceras, ampliable si el cliente mantiene un ritmo mínimo de 500 bytes/segundo (así no penaliza a clientes lentos legítimos, solo a los que no envían nada).
- `body=20,MinRate=500`: mismo criterio para el cuerpo de la petición.

Complementos adicionales en Apache:

```apache
Timeout 30
MaxKeepAliveRequests 100
KeepAliveTimeout 5
```

También existe **`mod_qos`** (Quality of Service), más granular, que permite limitar conexiones concurrentes por IP, ralentizar clientes sospechosos y priorizar tráfico legítimo:

```apache
<IfModule mod_qos.c>
    QS_SrvMaxConnPerIP 50
    QS_SrvMaxConnClose 80
    QS_ClientEventLimitCount 10
</IfModule>
```

### 3.2 Nginx

Nginx ya es estructuralmente resistente por su modelo asíncrono, pero conviene endurecer los timeouts igualmente:

```nginx
client_header_timeout 10s;
client_body_timeout 10s;
keepalive_timeout 5s 5s;
send_timeout 10s;

# Limitar conexiones concurrentes por IP
limit_conn_zone $binary_remote_addr zone=addr:10m;
limit_conn addr 20;

# Limitar tasa de nuevas conexiones
limit_req_zone $binary_remote_addr zone=req_limit:10m rate=10r/s;
limit_req zone=req_limit burst=20 nodelay;
```

### 3.3 IIS

```
Habilitar límites de conexión en IIS Manager:
- Site > Configuration Editor > system.applicationHost/sites > limits
  - connectionTimeout: 00:00:30
  - headerWaitTimeout (vía registro o Dynamic IP Restrictions)
- Habilitar "Dynamic IP Restrictions" para limitar conexiones concurrentes por IP
```

### 3.4 Tabla comparativa de mitigaciones por servidor

| Servidor | Mecanismo principal | Módulo/Config | Limita por IP | Nivel de esfuerzo |
|---|---|---|---|---|
| Apache HTTPD | Timeout de cabeceras/cuerpo | `mod_reqtimeout` | No (nativo) | Bajo |
| Apache HTTPD | QoS avanzado | `mod_qos` | Sí | Medio |
| Nginx | Timeouts + límites de conexión | `client_header_timeout`, `limit_conn` | Sí | Bajo |
| IIS | Timeouts + Dynamic IP Restrictions | Configuration Editor | Sí | Medio |
| lighttpd | Timeout de I/O | `server.max-write-idle` | No (nativo) | Bajo |
| Cualquiera | Filtrado en el borde | WAF / CDN / Reverse proxy | Sí | Bajo (delegado) |

### 3.5 Mitigación en el perímetro (WAF, CDN, balanceadores)

La defensa más robusta suele ser **no dejar que la conexión lenta llegue al servidor de aplicación**:

| Solución | Cómo mitiga Slowloris |
|---|---|
| Cloudflare / AWS CloudFront / Akamai | Terminan la conexión TCP/HTTP en el edge; el backend solo recibe peticiones completas y agregadas |
| AWS ALB / NLB con timeouts ajustados | El balanceador cierra conexiones inactivas antes de saturar los targets |
| HAProxy | `timeout http-request 10s` fuerza el cierre de conexiones con cabeceras incompletas |
| ModSecurity (WAF) | Reglas OWASP CRS incluyen detección de "slow HTTP DoS" |
| Fail2ban + iptables | Bloqueo automático de IPs con patrones de conexión lenta anómalos |

Ejemplo de configuración en HAProxy:

```haproxy
defaults
    timeout http-request 10s
    timeout queue         1m
    timeout connect       10s
    timeout client        30s
    timeout server        30s
```

### 3.6 Checklist rápido de hardening

| # | Medida | Prioridad |
|---|---|---|
| 1 | Configurar `mod_reqtimeout` (Apache) o timeouts nativos (Nginx) | Alta |
| 2 | Limitar conexiones concurrentes por IP | Alta |
| 3 | Habilitar monitorización de estado de workers (`mod_status`/`stub_status`) | Alta |
| 4 | Colocar un WAF/CDN delante del servidor de aplicación | Media-Alta |
| 5 | Definir alertas sobre nº de conexiones `ESTABLISHED` anómalo | Media |
| 6 | Revisar `KeepAliveTimeout` y `MaxKeepAliveRequests` | Media |
| 7 | Plan de respuesta (bloqueo automático vía Fail2ban/iptables) | Media |

---

## 4. Laboratorio controlado de aprendizaje

Este apartado describe cómo montar un entorno **aislado y propio** (sin conectividad hacia Internet ni hacia redes de terceros) para estudiar el comportamiento de Slowloris desde el punto de vista defensivo: observar el agotamiento de workers, practicar la detección y validar que las mitigaciones funcionan.

### 4.1 Objetivos de aprendizaje

- Comprender el efecto de una conexión HTTP lenta sobre el pool de workers de un servidor.
- Practicar el uso de herramientas de monitorización (`mod_status`, `ss`, Grafana) para detectar el agotamiento de recursos en tiempo real.
- Configurar y validar mitigaciones (`mod_reqtimeout`, `limit_conn` en Nginx, reglas de WAF) comparando el comportamiento del servidor antes y después.
- Practicar la escritura de alertas (Prometheus/Grafana o scripts propios) que disparen ante un patrón de conexiones lentas.

### 4.2 Topología recomendada

```
┌────────────────────────────┐        red interna aislada (host-only / NAT interno)
│   Máquina "atacante" (VM)   │──────────────┐
│   - Herramienta de test     │              │
│     de estrés HTTP lenta    │              ▼
└────────────────────────────┘   ┌────────────────────────────┐
                                  │   Máquina "servidor" (VM)   │
┌────────────────────────────┐   │   - Apache/Nginx vulnerable │
│  Máquina "monitor" (VM)     │◄──┤   - mod_status/stub_status  │
│  - Grafana/Prometheus       │   │   - Logs centralizados      │
│  - Dashboards de conexiones │   └────────────────────────────┘
└────────────────────────────┘
```

Recomendaciones:

- Usa una **red virtual interna** (host-only, NAT interno de VirtualBox/VMware, o una red `bridge` de Docker sin salida a Internet) para que el tráfico nunca salga de tu equipo.
- Etiqueta claramente las VMs (`lab-atacante`, `lab-servidor`, `lab-monitor`) para evitar confusiones con máquinas de producción.
- No expongas ningún puerto de estas VMs hacia tu red doméstica/corporativa ni hacia Internet.

### 4.3 Levantar el servidor de pruebas vulnerable

Ejemplo con Apache en Docker, en su configuración por defecto (sin `mod_reqtimeout`), para observar el efecto:

```bash
docker network create --internal lab-slowloris-net

docker run -d --name lab-servidor \
  --network lab-slowloris-net \
  -p 127.0.0.1:8080:80 \
  httpd:2.4
```

Habilita `mod_status` para poder observar el estado de los workers durante las pruebas:

```apache
# En httpd.conf del contenedor
LoadModule status_module modules/mod_status.so
<Location "/server-status">
    SetHandler server-status
    Require ip 127.0.0.1
</Location>
```

### 4.4 Fases de la práctica

| Fase | Objetivo | Qué observar |
|---|---|---|
| 1. Línea base | Medir capacidad normal del servidor (peticiones/seg, workers libres) | `server-status`, `ab`/`wrk` con carga normal |
| 2. Simulación de conexiones lentas | Generar conexiones que mantengan cabeceras incompletas contra el servidor de laboratorio | Nº de workers ocupados, tiempo de respuesta a clientes legítimos simulados |
| 3. Detección | Detectar el patrón anómalo con `ss`, `mod_status`, Grafana | Conexiones `ESTABLISHED` largas desde la VM atacante |
| 4. Mitigación | Aplicar `mod_reqtimeout` / `limit_conn` y repetir la fase 2 | Comparar nº de workers agotados antes/después |
| 5. Validación | Confirmar que un cliente legítimo sigue siendo atendido con la mitigación activa | Latencia y disponibilidad para tráfico normal |


#
http://www.hackingyseguridad.com/
#
