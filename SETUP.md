# Setup guide: detection stack

Step-by-step build for the pipeline described in the README. Zeek watches the wire, Kafka
buffers, the Wazuh/OpenSearch indexer stores and searches, MISP supplies indicators, and 12
custom rules turn all of it into alerts.

Budget 2 to 3 days. Most of it is the first `docker compose up` and rule tuning.

## Prerequisites

Ubuntu Server 22.04 VM, 8 GB RAM, 4 vCPU, 60 GB disk, two adapters (see the top-level
README). If you only have 6 GB, drop the MISP containers at first and add them on day two;
everything except rules 100005 and 100006 works without them.

```bash
sudo apt update && sudo apt install -y docker.io docker-compose-v2 jq dnsutils netcat-openbsd sshpass
sudo usermod -aG docker "$USER" && newgrp docker
sudo sysctl -w vm.max_map_count=262144
echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf
```

## 1. Install Zeek natively

Zeek needs the real interface, so it runs on the VM rather than in a container.

```bash
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' | \
  sudo tee /etc/apt/sources.list.d/zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key | \
  sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/zeek.gpg
sudo apt update && sudo apt install -y zeek-lts
echo 'export PATH=/opt/zeek/bin:$PATH' >> ~/.bashrc && source ~/.bashrc

zkg autoconfig && zkg install zeek-kafka          # the Kafka writer plugin
sudo mkdir -p /opt/zeek/intel
```

Copy the config in, **edit `Site::local_nets` to match your host-only subnet**, set the
capture interface, then start:

```bash
sudo cp zeek/local.zeek /opt/zeek/share/zeek/site/local.zeek
sudo sed -i 's/^interface=.*/interface=enp0s8/' /opt/zeek/etc/node.cfg   # your adapter 2
sudo zeekctl deploy && sudo zeekctl status
```

Getting `local_nets` wrong is the single most common mistake here: every internal host gets
treated as external, the direction logic inverts, and half the rules never fire.

## 2. Bring up the stack

```bash
docker compose up -d
docker compose ps          # wait until wazuh-indexer is healthy, ~5 min first run
```

- Wazuh dashboard: <https://localhost:5601> (`admin` / the password in your `.env`)
- MISP: <https://localhost:8443>
- OpenSearch API: <https://localhost:9200>

Set real passwords first:

```bash
cat > .env <<'EOF'
INDEXER_PASSWORD=<pick something>
MISP_DB_PASSWORD=<pick something>
MISP_DB_ROOT_PASSWORD=<pick something>
EOF
chmod 600 .env
```

## 3. Wire MISP into the rules

Create an automation key in the MISP UI (Administration → List Auth Keys), then:

```bash
pip3 install requests opensearch-py kafka-python
export MISP_URL=https://localhost:8443
export MISP_KEY=<automation key>
python3 scripts/misp_ingest.py
```

Register the CDB lists in `/var/ossec/etc/ossec.conf` inside the manager container, then
restart it:

```xml
<ruleset>
  <list>etc/lists/misp-domains</list>
  <list>etc/lists/misp-ips</list>
</ruleset>
```

## 4. Start the Kafka consumer

```bash
export OPENSEARCH_PASSWORD=<indexer password>
python3 scripts/kafka_to_opensearch.py
```

Confirm Zeek is actually producing:

```bash
docker exec kafka kafka-console-consumer.sh --bootstrap-server localhost:9092 \
  --topic zeek --max-messages 5
```

## 5. Onboard endpoints

One Linux and one Windows agent, because the CV says both. From the Wazuh dashboard:
*Agents → Deploy new agent*, follow the generated command. Then enable FIM on the paths
rules 100007 and 100008 watch, in each agent's `ossec.conf`:

```xml
<syscheck>
  <directories check_all="yes" realtime="yes">/etc,/bin,/sbin,/usr/bin,/usr/sbin,/boot</directories>
</syscheck>
```

## 6. Tune the rules, which is the part that matters

```bash
chmod +x scripts/replay_attacks.sh
./scripts/replay_attacks.sh <monitored-vm-ip>
```

Then count what fired:

```bash
jq -r '.rule.id' /var/ossec/logs/alerts/alerts.json | sort | uniq -c | sort -rn
```

Record the counts **before** you adjust anything, change the thresholds that are obviously
wrong for your environment, replay again, and record the counts **after**. Those two
columns are the evidence for "tuned them against replayed attack traffic". Without them the
claim is unsupported.

The thresholds in `local_rules.xml` carry inline comments explaining why each number is
what it is. Change them to fit what you actually observe, and update the comments. Being
able to say *why* 52 characters and not 40 is what separates authoring rules from
downloading them.

## 7. Demonstrate the Kafka decoupling

The reason Kafka is in the CV at all:

```bash
# stop the consumer, generate traffic, restart it
pkill -f kafka_to_opensearch.py
./scripts/replay_attacks.sh <target>
docker exec kafka kafka-consumer-groups.sh --bootstrap-server localhost:9092 \
  --group zeek-to-opensearch --describe          # note the LAG column
python3 scripts/kafka_to_opensearch.py           # watch it drain to zero
```

Screenshot the lag before and after. That is a 30-second interview answer.

## Fill in EVIDENCE.md as you go

Every CV claim from this lab is listed there with the exact command that produces its
evidence. Do it while the terminal is still open, not from memory a week later.
