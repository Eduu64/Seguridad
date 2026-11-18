# Seguridad para tu homelab Debian — en Docker

Stack de seguridad para un servidor Debian con Docker: **todo lo que puede vivir en contenedores, vive en contenedores** (CrowdSec, Caddy y panel web). La única excepción es el bouncer de firewall, que se instala **nativo con systemd** porque CrowdSec no publica imagen Docker oficial de él (comprobado en Docker Hub, 2026-11-18) y su trabajo — escribir iptables/ipset — es del kernel del host. Vigila el host, vigila **tus otros contenedores** leyendo sus logs, bloquea IPs atacantes en el firewall y te da las alertas desde un **panel web local con mapa**, desde la consola web oficial de CrowdSec (opcional) y desde la línea de comandos.

Diseñado para una máquina con **poca RAM y poco disco**: el stack completo (incluido el panel) consume ~300 MB de RAM en total. El antivirus ClamAV se llegó a incluir y se eliminó a petición expresa: su motor residente exige gigas de RAM que aquí no hay.

```
                       Internet
                          │  (router SIN puertos abiertos ✓)
   Tu LAN ───────────────►│
                          ▼
┌───────────────── HOST Debian (tu servidor) ─────────────────────────┐
│  iptables + ipset  ◄── crowdsec-firewall-bouncer (systemd NATIVO,   │
│        ▲                  paquete oficial .deb, ~15 MB)             │
│        │ decisiones                                                 │
│  ┌─────┴──────┐   lee logs vía docker.sock y /var/log/auth.log      │
│  │  crowdsec  │◄──── SSH del host + logs de tus contenedores + Caddy│
│  └─────┬──────┘                                                     │
│        │ alertas                                                    │
│        ▼                                                            │
│  panel:8096 (dashboard local con mapa, ~35 MB) · app.crowdsec.net   │
│  solo si TÚ te enrolas (opcional)                                   │
│                                                                     │
│  [caddy]  proxy inverso ligero (~50 MB) delante de tus servicios    │
└─────────────────────────────────────────────────────────────────────┘
```

## 1. Qué incluye

Imágenes **fijadas a versiones oficiales verificadas en Docker Hub** el 2026-11-18 (nada de `latest`: sabes exactamente qué ejecutas y actualizas cuando TÚ decidas, README §8):

| Servicio | Imagen/versión | Función | RAM aprox. | ¿Por defecto? |
|---|---|---|---|---|
| `crowdsec` | `crowdsecurity/crowdsec:v1.8.2` | Detecta ataques en logs (SSH, web, tus contenedores) y decide baneos | 100-200 MB | Sí |
| `crowdsec-firewall-bouncer` | **nativo** (paquete oficial .deb, systemd) | Aplica los baneos en iptables+ipset del host | ~15 MB | Sí (lo instala `setup.sh`) |
| `caddy` | `caddy:2.11.9-alpine` | Proxy inverso ligero con HTTPS automático; sus logs alimentan CrowdSec | ~50 MB | Sí |
| `panel` (+ `panel-setup` one-shot) | `python:3.13.18-alpine` + `crowdsec:v1.8.2` | Dashboard web local de CrowdSec: vistas completas, mapa, notificaciones (Discord/ntfy/Gotify), stats SQLite | ~35 MB | Sí |

Por qué Caddy y no Traefik/NPM: consumes menos RAM y espacio que los otros dos, el parser de CrowdSec (`crowdsecurity/caddy`) es oficial, y no pierde eficiencia — para servir y loguear hace exactamente lo mismo que los demás con una sola máquina Go. ¿Por qué sin antivirus (ClamAV)? Se llegó a incluir y se quitó: el motor residente (`clamd`) exige 1.2-3 GB de RAM solo para mantener las firmas en memoria, inviable en una máquina pequeña, y el escaneo puntual con `clamscan` sin demonio no tiene gestión útil desde un panel. Si algún día lo necesitas, se activa aparte — pero este stack va de controlar QUIÉN entra, no qué hay guardado.

## 2. Contenido del paquete

```
homelab-seguridad-docker/
├── docker-compose.yml              # los 4 servicios (2 del panel)
├── .env.example                    # variables → setup.sh genera tu .env real
├── setup.sh                        # preparación en un comando (idempotente; instala el bouncer nativo)
├── ver-alertas.sh                  # resumen de seguridad en un comando
├── README.md                       # este fichero
├── panel/
│   ├── panel.py                    # backend del panel: LAPI + escrituras protegidas + SQLite
│   └── index.html                  # el panel web (un solo fichero, sin recursos externos)
├── crowdsec/
│   ├── acquis.d/
│   │   ├── 01-host-ssh.yaml        # lee /var/log/auth.log (SSH del host)
│   │   └── 02-caddy.yaml           # lee los logs del contenedor caddy
│   ├── local-whitelists.yaml       # nunca banear tu LAN ni redes internas
│   └── db_config.yaml              # limita la BD de alertas (poco disco)
├── firewall-bouncer/
│   └── crowdsec-firewall-bouncer.yaml  # config que setup.sh copia a /etc/crowdsec/bouncers/ en el host
├── caddy/
│   └── Caddyfile                   # proxy inverso con ejemplo funcionando
```

## 3. Requisitos

- Debian 11/12/13 con **Docker + compose plugin** (`docker compose version` debe funcionar).
- Acceso por `sudo` en el host (para instalar el bouncer nativo y leer ipset/iptables).
- Si aún usas **fail2ban, quítalo** (CrowdSec lo sustituye y evitas doble trabajo):
  ```bash
  sudo systemctl disable --now fail2ban && sudo apt purge fail2ban
  ```
- Que **no** haya otro proxy en los puertos 80/443 del host (si lo hay, ver §11).

## 4. Instalación (3 pasos)

```bash
cd homelab-seguridad-docker
./setup.sh                  # genera .env, renderiza el bouncer e INSTALA crowdsec-firewall-bouncer nativo
docker compose up -d        # arranca crowdsec + caddy + panel
```

Qué hace exactamente `setup.sh` (idempotente, lo puedes reejecutar):
1. Crea `.env` con una clave aleatoria de 64 hex para la LAPI (y detecta el GID de docker.sock).
2. Renderiza `firewall-bouncer/crowdsec-firewall-bouncer.yaml` con esa clave y lo copia a `/etc/crowdsec/bouncers/` del host.
3. Si no existe, instala el bouncer **nativo** desde el repo oficial de paquetes de CrowdSec (`curl -sSL https://install.crowdsec.net -o /tmp/crowdsec-repo.sh && sudo sh /tmp/crowdsec-repo.sh` + `apt-get install crowdsec-firewall-bouncer ipset`) y lo deja como servicio systemd. Si no quieres que lo haga ahora: `SKIP_BOUNCER=1 ./setup.sh` (te deja impresas las 3 líneas para hacerlo a mano).
4. Avisa de lo que falte (docker, auth.log, puertos ocupados) antes de que intentes arrancar.

El registro del bouncer contra la LAPI es automático: el contenedor `crowdsec` acepta la clave vía `BOUNCER_KEY_firewall_bouncer`, así que no hay que correr `cscli bouncers add` a mano. El bouncer reintenta solo hasta que la LAPI está arriba (normal tras `docker compose up`).

## 5. Verificación paso a paso (hazla, son 2 minutos)

```bash
# 1) Los servicios UP (crowdsec, caddy, panel) y el bouncer activo en el host
docker compose ps
systemctl status crowdsec-firewall-bouncer

# 2) CrowdSec lee logs (busca "parsed" > 0 en la sección BUCKETS/PARSERS)
docker compose exec crowdsec cscli metrics

# 3) El bouncer está registrado y conectado
docker compose exec crowdsec cscli bouncers list     # firewall_bouncer, "last pull" reciente

# 4) Prueba de baneo real (usa una IP libre de tu LAN, p. ej. 192.168.1.99)
docker compose exec crowdsec cscli decisions add --ip 192.168.1.99 --duration 2m --reason "prueba"
#   En el HOST (ipset lo instala setup.sh si faltaba):
sudo ipset list crowdsec-blacklists | grep 192.168.1.99   # debe aparecer
sudo iptables -L INPUT -n | grep crowdsec                 # la regla que dropea el set

# 5) Limpia la prueba
docker compose exec crowdsec cscli decisions remove --ip 192.168.1.99
```

Desde ese momento cualquier ataque real (bruteforce SSH, escaneos, inyecciones web contra lo que pase por Caddy…) genera una alerta y la IP queda bloqueada en el firewall automáticamente.

## 6. Alertas: panel web local + consola oficial + CLI

**Panel web local — v2.2: `http://IP-DEL-SERVIDOR:8096`** (puerto configurable en `.env` con `PANEL_PORT`; usamos 8096 porque tus 8080/8090/3000 están ocupados). Es una interfaz **propia, en español, con el mismo diseño visual que crowdsec-web-ui** (misma paleta sky/gray, tipografía IBM Plex Sans incrustada, mismos iconos, layout y textos de cada vista; tema claro por defecto como sus capturas, con oscuro a un clic). **Abre sin login: es de solo lectura.** Sus vistas: **Panel** (tarjetas, mapa de ataques con zoom y toggle de marcadores, gráfico agrupado alertas/decisiones con modo lineal/apilado y 1D/1S, top países con %/lista, escenarios, AS y objetivos por servicio/máquina), **Alertas** (histórico paginado con búsqueda sintáctica `country:RU ip:1.2.3 scenario:ssh date:2026-11-18`, drawer de **filtros rápidos**, filtros guardados, **agrupar por IP**, **modal de detalle con eventos reales vía LAPI** y borrado por lotes), **Decisiones** (ban manual estilo "Add Decision" con duración `4h/30m/2d`, unban individual y por lotes, aviso de allowlist, expiración en vivo tipo `29h59m27s`, histórico de expiradas), **Estadísticas** (píldoras Hoy/7d/30d/Todo, hallazgos automáticos, cobertura de remediación, IPs recurrentes, /24 dominante, gráfico de líneas alertas vs decisiones), **Allowlists** (banner informativo + comprobador de IP, solo lectura), **Métricas** (contadores del panel + Prometheus de CrowdSec), **Notificaciones** (tarjetas resumen, historial, webhook opcional **Discord/ntfy/Gotify**, reglas con switches) y **Ajustes** (preferencias con toggles reales de la barra lateral, tema, sesión y auditoría).

Por qué es seguro (y ligero):

- **Sin login por defecto**: el panel abre directo y es de SOLO LECTURA — nadie puede banear, desbanear ni borrar nada desde el navegador. Si quieres acciones, define `PANEL_UI_PASSWORD=tuclave` en `.env` y recrea (`docker compose up -d --force-recreate panel`): entonces pide login, habilita las escrituras y aplican máx. 5 sesiones de 12 h, bloqueo de 5 min tras una ráfaga de fallos y auditoría de cada intento.
- **Escrituras blindadas** (ban/unban/borrado de alertas): exigen sesión + `Origin` propio + JSON estricto + token por cabecera custom (sin cookies y sin CORS, un formulario externo no puede forjarlas) + validación dura (IP real, duración máx. 30 días, motivo saneado, máx. 10 ops/min) + **auditoría de cada acción**, visible en Ajustes.
- **Credenciales propias de la LAPI**: `setup.sh` genera la contraseña watcher y el one-shot `panel-setup` registra al panel (`cscli machines add --force`, idempotente). El token de la LAPI vive dentro del contenedor; nunca llega al navegador.
- **Histórico y notificaciones en SQLite local** (volumen `panel-data`, unos MB): las estadísticas de largo plazo no tocan la BD de CrowdSec. Nada se envía fuera salvo el webhook que TÚ configures (Discord/ntfy/Gotify: solo el texto del aviso).
- **Cero recursos externos**: una única ficha HTML con CSS/JS inline, el mapa mundial y la fuente IBM Plex Sans **incrustados en base64** — sin CDNs, sin descargas de fuentes, sin imágenes ni librerías (verificado por test automático); cabeceras CSP + `nosniff` + `X-Frame-Options: DENY` y escape XSS en todo lo que pinta.
- **Ligero**: ~30-40 MB de RAM (vs 100-300 MB del original), sin Node, sin React, sin puerto 3000.
- **Solo tu LAN**: no hay puertos abiertos en el router; si quieres restringirlo aún más, fija la IP local en el mapeo del puerto (`192.168.1.10:8096:8096`).

**Notificaciones por webhook de Discord** (también vale ntfy/Gotify): configúralo en el panel (Notificaciones → editar destino) o en `.env` con `DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...` y `docker compose up -d --force-recreate panel`. Con esto el panel manda un mensaje a Discord por **cada baneo nuevo** y por los **picos de alertas** (≥ umbral por hora, configurable); el botón "Probar" envía un aviso de test. Lo que sale es únicamente el texto del aviso (título y una línea) hacia esa URL — nunca logs, ni configuración, ni el contenido de tus servicios. Si dejas la URL vacía, el panel no abre ninguna conexión externa.

**Comparativa honesta con `crowdsec-web-ui`** (el repo de referencia):

| Función del repo original | Este panel |
|---|---|
| **Diseño** (paleta, IBM Plex Sans, layout, iconos, textos) | ✔ clonado fielmente — fuente y mapa incrustados, claro/oscuro |
| Dashboard: totales, baneos activos, top atacantes | ✔ + LAPI Online + tops con %/lista y servicio/máquina |
| Historial de alertas con detalle (IP, AS, escenario) | ✔ + modal de detalle con eventos, búsqueda sintáctica, drawer de filtros, agrupar por IP y borrado por lotes |
| Mapa de ataques | ✔ — SVG incrustado, por país o coordenadas |
| Gráfico por horas | ✔ + por días en estadísticas |
| Estadísticas a largo plazo / tendencias | ✔ — SQLite local: 24 h/7 d/30 d/todo, comparación de periodos, IPs recurrentes, hallazgos automáticos |
| Baneos manuales (Add Decision) / unban | ✔ — con aviso de allowlist, validación estricta y auditoría |
| Borrar alertas (lotes) | ✔ — la LAPI exige `trusted_ips` (ver §11) |
| Allowlists | ✔ vista de solo lectura + comprobador de IP (igual que el original) |
| Notificaciones | ✔ campana local + reglas (baneo nuevo, pico) + webhook Discord/ntfy/Gotify (sin Apprise/SMTP/MQTT por simplicidad) |
| Métricas Prometheus | ✔ (panel propio siempre; las de CrowdSec al activar su listener 6060) |
| Login | opcional — sin contraseña es solo lectura; con contraseña: bloqueo anti fuerza bruta + auditoría (sin TOTP/passkeys/OIDC) |
| Tema claro/oscuro | ✔ (claro por defecto, como sus capturas; solo español, sin 12 idiomas) |
| Multi-instancia / SSO / roles de usuario | ✘ no aplican a un homelab de una sola LAPI |
| RAM | ~30-40 MB vs 100-300 MB del original |

Resultado: todo lo que tiene sentido para un homelab de una instancia, sin Node ni React ni sus tres bases de datos — backend Python estándar (~550 líneas) + una ficha HTML. Si aún así quisieras la app original, su contenedor (`ghcr.io/theduffman85/crowdsec-web-ui`) se añade al compose tal cual, pero rompe tus requisitos de consumo y ocupa el 3000.

**Para que el mapa tenga puntos**, CrowdSec necesita una base de geolocalización (no la trae de serie por licencia):

```bash
# Gratis con cuenta MaxMind: descarga GeoLite2-City.mmdb y GeoLite2-ASN.mmdb, y luego:
docker cp GeoLite2-City.mmdb crowdsec:/var/lib/crowdsec/data/
docker cp GeoLite2-ASN.mmdb crowdsec:/var/lib/crowdsec/data/
docker compose restart crowdsec
# Alternativa sin registro: dbip-country-lite.mmdb renombrado a GeoLite2-City.mmdb (solo país).
```

Sin esa base el panel funciona igual y el mapa queda sin puntos (el propio panel lo indica en pantalla). Los datos de la base NUNCA salen de tu servidor: se consultan localmente al generar la alerta.

**Consola web (app.crowdsec.net, gratis, 0 RAM extra en tu server):**

1. Crea cuenta en <https://app.crowdsec.net>.
2. En la consola: **Security Engines → Add Security Engine** → copia el comando de enrolamiento que te muestra.
3. Ejecútalo aquí con el token tuyo:
   ```bash
   docker compose exec crowdsec cscli console enroll TU_TOKEN_DE_LA_WEB
   docker compose exec crowdsec cscli console status
   ```
4. En la web ya verás tu engine con sus alertas. En **Blocklists** puedes suscribirte a las listas comunitarias: recibirás IPs maliciosas detectadas por miles de máquinas de todo el mundo y **tu bouncer las bloquea automáticamente**. Actívalas, es seguridad gratis.

**CLI local** (sin depender de la web):

```bash
docker compose exec crowdsec cscli alerts list        # historial de ataques
docker compose exec crowdsec cscli alerts inspect 42  # detalle de una alerta
docker compose exec crowdsec cscli decisions list     # IPs baneadas ahora mismo
docker compose exec crowdsec cscli metrics            # qué está analizando y con qué resultados
```

### Verlo en vivo, cada día

Lo más cómodo: `./ver-alertas.sh`, que te resume todo en un golpe. Y en detalle:

| Qué quieres ver | Comando |
|---|---|
| Resumen completo (servicios, baneos, últimas alertas) | `./ver-alertas.sh` |
| Alertas recientes (ataques detectados) | `docker compose exec crowdsec cscli alerts list --limit 20` |
| Detalle de una alerta concreta | `docker compose exec crowdsec cscli alerts inspect <ID>` |
| IPs baneadas ahora mismo | `docker compose exec crowdsec cscli decisions list` |
| Lo que entra, en vivo | `docker compose logs -f crowdsec` (procesado) · `docker compose logs -f caddy` (accesos web) |
| Baneos aplicados en el firewall del host | `sudo ipset list crowdsec-blacklists` |
| Desde el móvil/PC sin SSH | **panel web local** `http://IP:8096` · consola web app.crowdsec.net |

## 7. Proteger tus contenedores existentes ("control de los dockers de dentro")

CrowdSec ya vigila **todo el tráfico que llega al host** vía SSH y Caddy. Para que también analice los logs de un contenedor concreto, hay que darle dos cosas: leer sus logs y conocer su tipo de aplicación.

**Paso 1 — conecta el contenedor a la red de Caddy** (sin tocar sus compose):

```bash
docker network connect caddy-net NOMBRE_CONTENEDOR
```

**Paso 2 — publícalo en el Caddyfile** (`caddy/Caddyfile`), descomentando un bloque de ejemplo:

```
nextcloud.home.arpa {
    log
    reverse_proxy nextcloud:80
}
```

> La directiva `log` es imprescindible: genera el JSON de accesos que CrowdSec analiza. Sin ella, ese servicio no queda vigilado a nivel web.

**Paso 3 — añade sus logs a CrowdSec.** Crea un fichero nuevo en `crowdsec/acquis.d/` (por ejemplo `03-nextcloud.yaml`) con el nombre real del contenedor:

```yaml
source: docker
container_name_regexp:
  - "^nextcloud"
labels:
  type: nextcloud
```

Y si existe colección específica para esa app, añádela en el compose (`COLLECTIONS` del servicio crowdsec) y reinicia:

```bash
# Colecciones disponibles para apps típicas de homelab:
#   crowdsecurity/nextcloud   crowdsecurity/nginx   crowdsecurity/traefik
#   crowdsecurity/home-assistant              (domótica)
#   crowdsecurity/mysql  /  crowdsecurity/postgresql   (BD, si exponen logs de errores)
docker compose up -d --force-recreate crowdsec
```

Verifica con `docker ps --format '{{.Names}}'` que el nombre del contenedor coincide con la expresión regular que pusiste, y con `cscli metrics` que ya aparece como fuente con líneas `parsed`.

## 8. Mantenimiento

```bash
# Actualizar el stack (hazlo tú conscientemente, mejor que un watchtower ciego).
# Las imágenes están FIJADAS (v1.8.2 / 2.11.9-alpine / 3.13.18-alpine):
# para actualizar, sube la tag en docker-compose.yml a la versión oficial nueva
# (compruébala en hub.docker.com), luego:
docker compose pull && docker compose up -d

# El bouncer nativo se actualiza con el resto de paquetes del sistema:
sudo apt update && sudo apt install --only-upgrade crowdsec-firewall-bouncer

# Backup de la configuración/BD de CrowdSec (es pequeña):
docker run --rm -v homelab-seguridad-docker_crowdsec-config:/src:ro -v homelab-seguridad-docker_crowdsec-db:/db:ro \
  -v $(pwd):/dst alpine tar czf /dst/backup-crowdsec-$(date +%F).tgz -C /src . -C /db .

# Espacio en disco de logs de contenedores (crowdsec lee los json de docker):
docker system df
```

La BD de alertas ya está limitada (fichero `crowdsec/db_config.yaml`: máximo 5000 alertas y 7 días) para no crecer sin control.

## 9. Notas honestas de seguridad del propio stack

- **`/var/run/docker.sock` montado en `crowdsec` (read-only)**: es el patrón oficial de CrowdSec para leer logs de contenedores. Ten presente que el socket en lectura sigue exponiendo la API de Docker completa — es el precio de vigilar los contenedores desde dentro. Mitigación avanzada si algún día quieres más: poner un `docker-socket-proxy` (Hedgebox/tecnativa) que filtre a solo `GET` y apuntar `docker_host` del acquis a él.
- **`crowdsec-firewall-bouncer` corre NATIVO en el host (systemd)**: es el único componente fuera de Docker porque CrowdSec no publica imagen oficial (verificado en Docker Hub 2026-11-18) y su trabajo es escribir el netfilter del kernel, que es global al host. No publica puertos ni escucha red: solo consulta `127.0.0.1:8080` (la LAPI) y escribe iptables/ipset. Instalado y actualizado como paquete oficial .deb — más limpio y auditable que un contenedor community con `NET_ADMIN`.
- **El panel es el único componente con escrituras web** (ban/unban/borrar alertas): por eso su backend exige login + `Origin` propio + token de sesión + validación estricta + rate-limit, y registra cada acción en una auditoría visible en Ajustes. Sus credenciales watcher contra la LAPI solo valen dentro del host (la LAPI no está publicada más allá de `127.0.0.1:8080`).
- **Métricas y allowlist montados en solo lectura**: el panel lee el volumen `crowdsec-config` solo para pintar la allowlist; no puede escribir ninguna configuración de CrowdSec.
- Todo lo demás va con `no-new-privileges` y LAPI solo en `127.0.0.1:8080`.
- La whitelist de redes privadas (`crowdsec/local-whitelists.yaml`) evita auto-baneos de tus dispositivos y contenedores; bórrala solo si aceptas ese riesgo.

**Aislamiento de red — qué SALE y qué ENTRA, sin adornos:**

- **El panel: sin tráfico externo por defecto, verificado por test automático.** El HTML no contiene ni una referencia externa y, aun si las tuviera, la cabecera CSP del backend las bloquearía. Todo el mapa y los gráficos se calculan en tu navegador con datos de tu LAPI. **Únicas excepciones, y solo si TÚ las configuras:** (1) el webhook de notificaciones (`DISCORD_WEBHOOK_URL` — Discord, ntfy o Gotify; sale solo el texto del aviso) y (2) si defines `PANEL_UI_PASSWORD`, nada cambia en red: el login es interno.
- **Entra desde internet: nada.** El router no tiene puertos abiertos. Dentro del host solo escuchan Caddy (80/443, tu LAN), el panel (8096, tu LAN) y la LAPI en `127.0.0.1:8080` (solo el propio host).
- **Lo único que sale de tu red, y cuándo**: descarga de imágenes al desplegar (Docker Hub, versiones fijadas); CrowdSec refresca el hub al recrear/actualizar y SOLO habla con `app.crowdsec.net` si te enrolas (opcional); el webhook de Discord SOLO si lo configuraste; Caddy pediría certificados públicos SOLO si publicas un dominio real — con `.home.arpa` usa su CA interna y no sale nada.
- **Bouncer nativo**: cero tráfico de red; trabaja contra iptables local del host y consulta la LAPI en loopback.

## 10. Desinstalar / rollback

```bash
docker compose down                     # para todo lo que está en Docker
sudo systemctl disable --now crowdsec-firewall-bouncer   # para el bouncer nativo
sudo apt install ipset && sudo ipset destroy crowdsec-blacklists 2>/dev/null || true
docker network rm caddy-net 2>/dev/null || true
# Los volúmenes con config/BD se conservan; bórralos si quieres desde cero:
# docker volume rm homelab-seguridad-docker_crowdsec-config homelab-seguridad-docker_crowdsec-db ...
# Para eliminar el bouncer del sistema: sudo apt purge crowdsec-firewall-bouncer
```

## 11. Problemas frecuentes

| Síntoma | Causa y solución |
|---|---|
| El bouncer no conecta (`systemctl status` falla o no tira) | La clave no coincide con la de CrowdSec o la LAPI no está arriba: comprueba `docker compose ps` y `sudo journalctl -u crowdsec-firewall-bouncer -e`. Reejecuta `./setup.sh` (recopia la config) y `docker compose up -d`. |
| `cscli metrics` muestra `parsed: 0` | El nombre en el `acquis.d` no coincide con el contenedor real (`docker ps --format '{{.Names}}'` es tu amigo) o el `labels: type` no corresponde a la app. |
| CrowdSec no lee nada de SSH | No existe `/var/log/auth.log`: `sudo apt install rsyslog` o elimina el volumen `auth.log` del compose y el fichero `01-host-ssh.yaml`. |
| Caddy no arranca | Puertos 80/443 ocupados: cambia el mapeo en el compose (p. ej. `"8080:80"`) o detén el otro servicio. |
| El panel no carga datos (502 en pantalla) | Mira `docker logs panel` y `docker logs panel-setup`. Si el registro del watcher falló: reejecuta `./setup.sh && docker compose up -d --force-recreate panel-setup panel`. |
| El panel pide contraseña | Solo pasa si definiste `PANEL_UI_PASSWORD` en `.env`. Por defecto NO hay login (solo lectura). Si la cambias: `docker compose up -d --force-recreate panel`. |
| "Escrituras bloqueadas" en el panel | `PANEL_UI_PASSWORD` está vacía en `.env`: pon una contraseña y recrea el panel. Sin ella el panel es de solo lectura por diseño. |
| No llega nada a Discord | Comprueba la URL en Notificaciones → "Probar" (el aviso de prueba marca ✔/✘ en el historial). La URL debe ser un webhook válido `https://discord.com/api/webhooks/...`; mira `docker logs panel` si falla. |
| No puedo borrar alertas (403) | La LAPI de CrowdSec solo acepta borrados desde IPs de confianza: añade la red de Docker a `api.server.trusted_ips` en `/etc/crowdsec/config.yaml` (dentro del volumen `crowdsec-config`) y `docker compose restart crowdsec`. Ban/unban no lo necesitan. |
| Métricas de CrowdSec vacías en el panel | Activa el listener Prometheus: descomenta el bloque `prometheus:` (`enabled: true`, puerto 6060) en `/etc/crowdsec/config.yaml` y `docker compose restart crowdsec`. |
| Quiero notificaciones fuera de la campana | Pon `DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...` (o tu ntfy/Gotify) en `.env` y recrea el panel. |
| El puerto del panel está ocupado | Pon otro `PANEL_PORT` en `.env` y recrea: `docker compose up -d --force-recreate panel`. |
| Baneo no aplicado en el host | Comprueba `sudo iptables -L INPUT -n | grep crowdsec`; si tu Debian usa nftables puro y falla, cambia `mode: ipset` por `mode: nftables` en `firewall-bouncer/crowdsec-firewall-bouncer.yaml`, cópialo a `/etc/crowdsec/bouncers/` y `sudo systemctl restart crowdsec-firewall-bouncer`. |
| Ban correcto pero sigo accediendo desde mi PC | Estás en la whitelist de redes privadas — así está diseñado. Prueba baneando una IP fuera de tu LAN. |
