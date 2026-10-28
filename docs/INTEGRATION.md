# Integration guide

This covers the integration work that has to happen outside the codebase:
getting real logs from your security lab into API Fortress, and placing the
gateway in front of a different API.

---

## 1. Real security logs

Supported formats are detected per record, so a file can be uploaded with
*Detect automatically*. All are JSON (one object per line, a JSON array, or an
OpenSearch export with `hits.hits[]._source`).

### 1.1 Wazuh

Wazuh writes alerts on the **manager** to `/var/ossec/logs/alerts/alerts.json`.

```bash
# on the Wazuh manager
sudo tail -n 5000 /var/ossec/logs/alerts/alerts.json > ~/wazuh_alerts.json
# copy to your laptop (from your laptop)
scp user@<wazuh-manager>:~/wazuh_alerts.json .
```

If you use the Wazuh all-in-one Docker deployment:

```bash
docker exec single-node-wazuh.manager-1 tail -n 5000 /var/ossec/logs/alerts/alerts.json > wazuh_alerts.json
```

Fields used: `timestamp`, `rule.id/level/description/groups`, `agent`, `data.srcip/srcuser/url/id`, `full_log`.
Wazuh level → severity: 0–3 info, 4–6 low, 7–9 medium, 10–12 high, 13–15 critical.

### 1.2 Suricata

Suricata writes EVE JSON to `/var/log/suricata/eve.json`. Keep the security-relevant records:

```bash
jq -c 'select(.event_type=="alert" or .event_type=="http" or .event_type=="anomaly")' \
   /var/log/suricata/eve.json | tail -n 5000 > suricata_eve.json
```

(Without `jq`: `tail -n 5000 /var/log/suricata/eve.json > suricata_eve.json` — `stats`
and `flow` records are skipped automatically.)

To generate alerts in a lab, run a scan from another VM against the monitored host,
e.g. `nmap -sV <target>` or `nikto -h http://<target>`.

Suricata `alert.severity` → severity: 1 high, 2 medium, 3 low.

### 1.3 ModSecurity (OWASP CRS)

Enable JSON audit logging (Nginx connector example, `/etc/nginx/modsec/modsecurity.conf`):

```
SecRuleEngine On
SecAuditEngine RelevantOnly
SecAuditLogParts ABIJDEFHZ
SecAuditLogFormat JSON
SecAuditLogType Serial
SecAuditLog /var/log/modsec_audit.json
```

```bash
sudo nginx -t && sudo systemctl reload nginx
curl "http://<host>/?q=' OR 1=1--"      # generates a CRS 942100 event
sudo cp /var/log/modsec_audit.json ~/ && sudo chown $USER ~/modsec_audit.json
```

### 1.4 Importing

- **Dashboard**: *Log ingestion* → drop the file → *Import and analyse*.
- **Command line, once**:
  ```bash
  curl -X POST "https://<gateway>/admin/api/ingest/push?source=wazuh" \
       -H "X-Ingest-Token: <INGEST_TOKEN>" --data-binary @wazuh_alerts.json
  ```

### 1.5 Continuous shipping

`scripts/ship_logs.py` uses only the Python standard library, so it runs directly
on the Wazuh manager or Suricata sensor.

1. Set `INGEST_TOKEN` in the gateway's `.env` (or on Render) and restart.
2. Copy `scripts/ship_logs.py` to the sensor host.
3. Run:
   ```bash
   sudo python3 ship_logs.py --file /var/ossec/logs/alerts/alerts.json \
        --source wazuh --url https://<gateway> --token <INGEST_TOKEN> --follow
   ```
   It sends the last 5,000 lines, then new lines every 10 seconds in batches of
   500. Its read position is saved so a restart does not resend data.

Run it as a service (systemd) so it survives reboots:

```ini
# /etc/systemd/system/fortress-shipper.service
[Unit]
Description=API Fortress log shipper
After=network-online.target

[Service]
Environment=INGEST_TOKEN=<token>
ExecStart=/usr/bin/python3 /opt/fortress/ship_logs.py --file /var/log/suricata/eve.json --source suricata --url https://<gateway> --follow
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now fortress-shipper
```

If the gateway runs on your laptop and the sensor is a VM on the same machine, use
the laptop's host-only/NAT IP (e.g. `http://192.168.56.1:8000`) and start the
gateway with `python run_local.py --host 0.0.0.0`. Allow port 8000 in Windows Firewall when prompted.

### 1.6 Sanitising logs before sharing

Logs can contain real IPs, usernames and hostnames. Before committing samples or
sharing screenshots, anonymise them, for example:

```bash
sed -E 's/\b10\.0\.[0-9]+\.[0-9]+\b/10.0.0.X/g' wazuh_alerts.json > wazuh_alerts.sanitised.json
```

### 1.7 Evaluating detection

The *Threat logs* page and CSV export give per-rule match counts. If your dataset
has ground-truth labels (for example, you recorded which source IP was your
attacker VM and when), export the CSV and compare `classification` against the
labels to compute precision and recall. Without labels, report counts and
examples only.

---

## 2. Putting the gateway in front of another API

1. Point the gateway at your API in `.env`:
   ```
   BACKEND_URL=http://127.0.0.1:5000
   PUBLIC_PATHS=/auth/login,/health,/docs
   ```
2. **Tokens**: set `JWT_SECRET`, `JWT_ALGORITHM`, `JWT_ISSUER` and `JWT_AUDIENCE`
   to match how your API issues tokens. The `sub` claim is used as the user identity
   and `role: admin` bypasses ownership checks.
3. **Prevent bypass**: make your API reject requests that lack the
   `X-Gateway-Secret` header (see `demo_api/main.py` → `require_gateway`), or bind it
   to `127.0.0.1` / a private network only.
4. **Ownership rules**: add an entry to `PROTECTED_RESOURCES` in
   `app/security/authorization.py`:
   ```python
   ResourceRule(
       name="order",
       pattern=re.compile(r"^/api/orders/(?P<id>\d+)/?$"),
       methods=frozenset({"GET", "PUT", "DELETE"}),
       owner_lookup="/internal/orders/{id}/owner",
   ),
   ```
   and expose `GET /internal/orders/{id}/owner` on your API returning
   `{"owner": "<username>"}` (404 if missing), protected by the shared secret.
5. The gateway forwards `X-Authenticated-User`, `X-Authenticated-Role` and
   `X-Request-ID`; any client-supplied versions of these headers are stripped.
6. Start in **Learning** mode, exercise the application, review *Policy → Learned
   endpoints*, then move to **Monitor**, review flagged events, and finally **Enforce**.
