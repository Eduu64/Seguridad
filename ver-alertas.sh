#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# ver-alertas.sh — resumen de seguridad en un solo comando
#   ./ver-alertas.sh        (o: bash ver-alertas.sh)
# Muestra: estado de los servicios, baneos activos, últimas alertas,
# bouncers conectados y estado del enrolamiento en la consola oficial.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail
cd "$(dirname "$0")"

GREEN='\033[1;32m'; NC='\033[0m'
sec() { printf "\n${GREEN}═══ %s ═══${NC}\n" "$*"; }

sec "Servicios del stack"
docker compose ps

sec "Baneos activos ahora mismo"
docker compose exec -T crowdsec cscli decisions list 2>/dev/null || echo "(crowdsec no responde)"

sec "Últimas 10 alertas"
docker compose exec -T crowdsec cscli alerts list --limit 10 2>/dev/null || true

sec "Bouncers conectados"
docker compose exec -T crowdsec cscli bouncers list 2>/dev/null || true

sec "Consola oficial (estado de enrolamiento)"
docker compose exec -T crowdsec cscli console status 2>/dev/null | head -10 || true

sec "Siguientes pasos útiles"
echo "  Panel web local:          http://IP-DEL-SERVIDOR:${PANEL_PORT:-8096}  (sin login; escrituras con PANEL_UI_PASSWORD)"
echo "  Bouncer en el host:       systemctl status crowdsec-firewall-bouncer"
echo "  Detalle de una alerta:    docker compose exec crowdsec cscli alerts inspect <ID>"
echo "  Métricas de análisis:     docker compose exec crowdsec cscli metrics"
echo "  Logs en vivo:             docker compose logs -f crowdsec  |  docker compose logs -f caddy"
echo "  IPs baneadas en el host:  sudo ipset list crowdsec-blacklists"
