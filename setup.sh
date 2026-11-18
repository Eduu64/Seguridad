#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# setup.sh — prepara el stack de seguridad antes del primer docker compose up
#   1. Genera .env desde .env.example (claves del bouncer y del panel + GID docker.sock)
#   2. Renderiza la configuración del bouncer con esa clave
#   3. Instala el bouncer de firewall NATIVO en el host (no existe imagen Docker
#      oficial de CrowdSec para él: comprobado en Docker Hub 2026-11-18)
#   4. Crea los directorios que montan los servicios
# Es idempotente: puedes ejecutarlo varias veces sin romper nada.
#   SKIP_BOUNCER=1 ./setup.sh   → si no quieres que instale el bouncer ahora
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")"

say()  { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }

# ── 1. .env ───────────────────────────────────────────────────────────────────
if [[ ! -f .env ]]; then
  cp .env.example .env
  chmod 600 .env
  KEY="$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  sed -i "s/^CROWDSEC_BOUNCER_KEY=.*/CROWDSEC_BOUNCER_KEY=${KEY}/" .env
  say "Creado .env con clave aleatoria para el bouncer"
else
  say ".env ya existe, se conserva"
fi

# shellcheck disable=SC1091
source .env

if [[ -z "${CROWDSEC_BOUNCER_KEY:-}" ]]; then
  KEY="$(openssl rand -hex 32)"
  sed -i "s/^CROWDSEC_BOUNCER_KEY=.*/CROWDSEC_BOUNCER_KEY=${KEY}/" .env
  CROWDSEC_BOUNCER_KEY="${KEY}"
  say "La clave del bouncer estaba vacía: generada ahora"
fi

if [[ -z "${PANEL_WATCHER_PASSWORD:-}" ]]; then
  sed -i "s/^PANEL_WATCHER_PASSWORD=.*/PANEL_WATCHER_PASSWORD=$(openssl rand -hex 16)/" .env
  say "Contraseña watcher del panel generada (PANEL_WATCHER_PASSWORD)"
fi

# PANEL_UI_PASSWORD se deja VACÍO a propósito: el panel abre SIN LOGIN y en
# solo lectura. Si más adelante quieres banear desde el panel, define esa
# variable en .env y recrea el panel (se lo recuerda el mensaje final).

# ── 2. GID del grupo docker (para que crowdsec pueda leer docker.sock) ────────
if [[ -S /var/run/docker.sock ]]; then
  DOCKER_GID="$(stat -c %g /var/run/docker.sock)"
  sed -i "s/^GID=.*/GID=${DOCKER_GID}/" .env
  say "GID del socket de Docker detectado: ${DOCKER_GID}"
else
  warn "No hay /var/run/docker.sock en esta máquina (¿docker instalado?)."
  warn "CrowdSec no podrá leer logs de contenedores hasta que docker funcione."
fi

# ── 3. Renderizar la config del bouncer con la clave ──────────────────────────
sed -i "s/__BOUNCER_KEY__/${CROWDSEC_BOUNCER_KEY}/" firewall-bouncer/crowdsec-firewall-bouncer.yaml
say "Configuración del bouncer lista (firewall-bouncer/crowdsec-firewall-bouncer.yaml)"

# ── 4. Bouncer de firewall NATIVO (systemd) ───────────────────────────────────
# CrowdSec no publica imagen Docker oficial de firewall-bouncer y su trabajo es
# tocar el netfilter del kernel del host: se instala como paquete oficial .deb.
install_bouncer() {
  if [[ -x /usr/bin/crowdsec-firewall-bouncer ]] || systemctl list-unit-files 2>/dev/null | grep -q crowdsec-firewall-bouncer; then
    say "firewall-bouncer ya está instalado en el host (se conserva tal cual)"
    return 0
  fi
  if [[ "${SKIP_BOUNCER:-0}" == "1" ]]; then
    warn "SKIP_BOUNCER=1: el bouncer de firewall NO se instala ahora"
    return 0
  fi
  if ! command -v apt-get >/dev/null 2>&1; then
    warn "No hay apt-get: instala el bouncer a mano (https://docs.crowdsec.net/u/bouncers/firewall/)"
    return 0
  fi
  local SUDO=""
  if [[ $EUID -ne 0 ]]; then
    if sudo -n true 2>/dev/null; then SUDO="sudo"
    else
      warn "Este paso necesita sudo. Ejecuta estas 3 líneas y vuelve a lanzar ./setup.sh:"
      echo "    curl -sSL https://install.crowdsec.net -o /tmp/crowdsec-repo.sh && sudo sh /tmp/crowdsec-repo.sh"
      echo "    sudo apt-get update && sudo apt-get install -y crowdsec-firewall-bouncer ipset"
      echo "    sudo cp ${PWD}/firewall-bouncer/crowdsec-firewall-bouncer.yaml /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml && sudo systemctl restart crowdsec-firewall-bouncer"
      return 0
    fi
  fi
  say "Instalando crowdsec-firewall-bouncer nativo (repo oficial de paquetes de CrowdSec)…"
  curl -sSL https://install.crowdsec.net -o /tmp/crowdsec-repo.sh
  $SUDO sh /tmp/crowdsec-repo.sh
  DEBIAN_FRONTEND=noninteractive $SUDO apt-get update -qq
  DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y -qq crowdsec-firewall-bouncer ipset >/dev/null
  $SUDO mkdir -p /etc/crowdsec/bouncers
  $SUDO cp firewall-bouncer/crowdsec-firewall-bouncer.yaml /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml
  $SUDO systemctl enable crowdsec-firewall-bouncer >/dev/null 2>&1 || true
  $SUDO systemctl restart crowdsec-firewall-bouncer 2>/dev/null || true
  say "firewall-bouncer instalado y activado (reintentará solo hasta que suba crowdsec:8080)"
}
install_bouncer

# ── 5. Comprobaciones amables (avisan, no bloquean) ──────────────────────────
command -v docker >/dev/null 2>&1 || warn "docker no encontrado: instálalo antes de docker compose up"

if [[ -f /var/log/auth.log ]]; then
  say "Log de SSH del host encontrado (/var/log/auth.log)"
else
  warn "No existe /var/log/auth.log: el host puede no llevar rsyslog."
  warn "  → sudo apt install rsyslog   (o quita el volumen de auth.log del compose)"
fi

if command -v docker >/dev/null 2>&1 && ss -ltn 2>/dev/null | grep -qE ':(80|443) '; then
  warn "Puertos 80/443 ya ocupados en el host (¿otro proxy o apache?)."
  warn "  → Caddy no arrancará hasta que liberes esos puertos o cambies el mapeo en el compose."
fi

PANEL_PORT="${PANEL_PORT:-8096}"
if command -v ss >/dev/null 2>&1 && ss -ltn 2>/dev/null | grep -qE ":${PANEL_PORT} "; then
  warn "El puerto del panel (${PANEL_PORT}) ya está ocupado en el host."
  warn "  → Pon otro PANEL_PORT en .env y recrea con: docker compose up -d --force-recreate panel"
fi

cat <<'EOF'

Siguiente paso:
  docker compose up -d          # stack base (crowdsec + caddy + panel)
  docker compose ps             # comprobar que los servicios están UP
  docker compose logs -f crowdsec   # si algo falla
  systemctl status crowdsec-firewall-bouncer   # el bouncer (nativo, systemd)

Panel web local (SIN login):  http://IP-DEL-SERVIDOR:8096
  → cualquiera de tu LAN puede VER alertas, mapa y estadísticas.
  → Las escrituras (ban/unban/borrar) están bloqueadas: es un panel de solo lectura.
  → ¿Quieres acciones desde el panel? Pon PANEL_UI_PASSWORD=tuclave en .env y:
      docker compose up -d --force-recreate panel
EOF
