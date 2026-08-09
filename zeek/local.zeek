##! Zeek site config for the detection lab.
##!
##! Loaded from /opt/zeek/share/zeek/site/local.zeek.
##! Ships every active log to the Kafka topic "zeek"; the Kafka consumer in
##! scripts/kafka_to_wazuh.py drains it into the Wazuh/OpenSearch indexer.
##!
##! Why Kafka sits in the middle at all: without it Zeek writes straight to disk
##! and a slow or restarting indexer silently loses events. With it, Zeek keeps
##! producing and the consumer catches up from its offset. That is the single
##! sentence to have ready if you are asked why the broker is there.

@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssh
@load base/protocols/ssl
@load base/frameworks/notice
@load base/frameworks/intel
@load policy/frameworks/intel/seen
@load policy/protocols/ssh/detect-bruteforcing
@load policy/protocols/conn/known-hosts

# ---------------------------------------------------------------- Kafka out --
# Requires the zeek-kafka package:  zkg install zeek-kafka
@load packages/zeek-kafka

redef Kafka::topic_name = "zeek";
redef Kafka::send_all_active_logs = T;
redef Kafka::tag_json = T;
redef Kafka::kafka_conf = table(
    ["metadata.broker.list"] = "127.0.0.1:9092"
);

# JSON on disk too, so the Wazuh manager can also tail the files directly.
# Belt and braces: if the Kafka consumer is down you still have the logs.
redef LogAscii::use_json = T;

# ------------------------------------------------------------ Intel from MISP --
# scripts/misp_ingest.py writes this file. Zeek's intel framework matches
# every seen indicator against it and raises Intel::Notice on a hit.
redef Intel::read_files += {
    "/opt/zeek/intel/misp-indicators.dat"
};

# ------------------------------------------------------------- Tuning ---------
# Local networks: adjust to your VM's host-only subnet before first run, or
# every internal host is treated as external and the direction logic inverts.
redef Site::local_nets = {
    192.168.56.0/24,
    10.0.2.0/24,
};

# SSH brute force threshold. Deliberately lower than the Zeek default of 30 so
# the lab produces hits inside a short replay run.
redef SSH::password_guesses_limit = 8;

# Flag long-lived connections moving a lot of data outbound. Crude exfil proxy,
# but it is honest about what it is and it fires on the replay script.
event connection_state_remove(c: connection)
    {
    if ( ! Site::is_local_addr(c$id$orig_h) )
        return;
    if ( c$orig$size > 50000000 )   # 50 MB out from an internal host
        NOTICE([$note=Notice::Tally,
                $msg=fmt("Large outbound transfer: %s -> %s, %d bytes",
                         c$id$orig_h, c$id$resp_h, c$orig$size),
                $conn=c]);
    }
