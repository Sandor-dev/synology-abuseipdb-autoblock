#!/bin/sh
# Synology DSM 7.x Auto Block - AbuseIPDB high-confidence IP import
# Default: 1-day list (~50-55k IPs), 10-day expiration
# Safe for the ~80k Auto Block limit.
#
# Usage (as root):
#   /bin/sh /volume1/scripts/block_list.sh
#
# Optional arguments:
#   $1 = list URL (default: s100-1d)
#   $2 = expiration days (default: 10)
#   $3 = Meta tag (default: abuseipdb-s100-1d)
#
# Requires: curl, awk, sqlite3 (all present on DSM)
# Auto Block must be enabled in Control Panel → Security → Protection

set -eu

URL="${1:-https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/main/abuseipdb-s100-1d.ipv4}"
DAYS="${2:-10}"
META="${3:-abuseipdb-s100-1d}"

DB="/etc/synoautoblock.db"
TMP="/tmp/abuseipdb-import.txt"
SQL="/tmp/abuseipdb-import.sql"
NOW=$(date +%s)
EXPIRE=$((NOW + DAYS * 86400))

log() { logger -t abuseipdb "$*"; echo "$*"; }

[ "$(id -u)" -eq 0 ] || { echo "Root kell."; exit 1; }
[ -f "$DB" ] || { log "Nincs $DB — kapcsold be az Automatikus blokkolást."; exit 1; }

curl -fsSL --max-time 90 "$URL" -o "$TMP" || { log "Letöltés sikertelen"; exit 1; }

LINES=$(grep -c . "$TMP" || true)
log "Letöltve: $LINES sor"

# Remove only our own expired entries
sqlite3 "$DB" "DELETE FROM AutoBlockIP WHERE Deny=1 AND Meta='$META' AND ExpireTime>0 AND ExpireTime < $NOW;"

echo "BEGIN;" > "$SQL"
awk -v now="$NOW" -v expire="$EXPIRE" -v meta="$META" '
  function okip(s, a) {
    if (s !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) return 0
    split(s, a, ".")
    if (a[1]>255 || a[2]>255 || a[3]>255 || a[4]>255) return 0
    if (a[1]==10 || a[1]==127 || a[1]==0) return 0
    if (a[1]==169 && a[2]==254) return 0
    if (a[1]==192 && a[2]==168) return 0
    if (a[1]==172 && a[2]>=16 && a[2]<=31) return 0
    return 1
  }
  {
    gsub(/\r/, "")
    sub(/#.*/, "")
    ip = $1
    if (ip=="") next
    if (!okip(ip)) next
    split(ip, o, ".")
    ipv6 = sprintf("0000:0000:0000:0000:0000:FFFF:%02X%02X:%02X%02X", o[1], o[2], o[3], o[4])
    printf "INSERT OR IGNORE INTO AutoBlockIP (IP,RecordTime,ExpireTime,Deny,IPStd,Type,Meta) VALUES('\''%s'\'',%s,%s,1,'\''%s'\'',0,'\''%s'\'');\n", ip, now, expire, ipv6, meta
  }
' "$TMP" >> "$SQL"
echo "COMMIT;" >> "$SQL"

INS=$(grep -c "^INSERT" "$SQL" || true)
log "SQL INSERT sorok: $INS"
[ "$INS" -gt 0 ] || { log "Nincs feldolgozható IP"; rm -f "$TMP" "$SQL"; exit 1; }

BEFORE=$(sqlite3 "$DB" "SELECT COUNT(*) FROM AutoBlockIP WHERE Deny=1;")
ERR=$(sqlite3 "$DB" < "$SQL" 2>&1) || { log "SQLite hiba: $ERR"; exit 1; }
AFTER=$(sqlite3 "$DB" "SELECT COUNT(*) FROM AutoBlockIP WHERE Deny=1;")
OURS=$(sqlite3 "$DB" "SELECT COUNT(*) FROM AutoBlockIP WHERE Meta='$META';")

rm -f "$TMP" "$SQL"
log "Kész. Deny: $BEFORE -> $AFTER | $META: $OURS | lejárat ${DAYS} nap"
