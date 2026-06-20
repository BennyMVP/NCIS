from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, arp, ipv4, tcp, udp
from ryu.lib import hub

import os
import time
import joblib
import numpy as np
import pandas as pd


PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MODEL_PATH = os.path.join(PROJECT_DIR, "ml", "best_model.joblib")

PROTECTED_SERVER_IP = "10.0.0.4"

# Parametri per rilevare traffico distribuito verso h4
AGG_MIN_SOURCES = 2
AGG_MIN_PACKET_RATE = 100.0
AGG_MIN_ACTIVE_FLOWS = 2

# Blocca dopo N rilevazioni consecutive
SUSPICIOUS_LIMIT = 4

# Durata blocco in secondi
BLOCK_TIMEOUT = 300


class MLDetectorControllerFinal(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MLDetectorControllerFinal, self).__init__(*args, **kwargs)

        self.mac_to_port = {}
        self.datapaths = {}
        self.prev_stats = {}
        self.suspicious_counts = {}
        self.blocked_flows = {}
        # formato: (dpid, src_ip, dst_ip) -> timestamp fine blocco

        model_package = joblib.load(MODEL_PATH)

        self.model = model_package["model"]
        self.threshold = float(model_package.get("threshold", 0.50))
        self.feature_columns = model_package.get("feature_columns", [])

        self.logger.info("Controller ML aggregato avviato")
        self.logger.info("Modello caricato: %s", model_package.get("model_name", "unknown"))
        self.logger.info("Soglia decisionale: %.2f", self.threshold)
        self.logger.info("Feature usate (%d): %s", len(self.feature_columns), self.feature_columns)

        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, priority=0, match=match, actions=actions)

        self.logger.info("Switch inizializzato: %s", datapath.id)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath

        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.datapaths[datapath.id] = datapath
                self.logger.info("Switch registrato: %s", datapath.id)

        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
                self.logger.info("Switch rimosso: %s", datapath.id)

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout
        )
        datapath.send_msg(mod)

    def add_drop_flow(self, datapath, src_ip, dst_ip):
        parser = datapath.ofproto_parser

        key = (datapath.id, src_ip, dst_ip)
        now = time.time()

        # Se il flow è già bloccato e il timeout non è scaduto, non reinstallo la regola.
        if key in self.blocked_flows and self.blocked_flows[key] > now:
            return

        # Se il timeout è scaduto, posso reinstallare il blocco in caso di nuovo attacco.
        if key in self.blocked_flows and self.blocked_flows[key] <= now:
            del self.blocked_flows[key]

        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=src_ip,
            ipv4_dst=dst_ip
        )

        self.add_flow(
            datapath=datapath,
            priority=200,
            match=match,
            actions=[],
            idle_timeout=0,
            hard_timeout=BLOCK_TIMEOUT
        )

        self.blocked_flows[key] = time.time() + BLOCK_TIMEOUT
        self.logger.warning(
            "BLOCCO INSTALLATO: %s -> %s per %s secondi",
            src_ip,
            dst_ip,
            BLOCK_TIMEOUT
        )

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            return

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        src_mac = eth.src
        dst_mac = eth.dst

        self.mac_to_port[dpid][src_mac] = in_port

        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if out_port != ofproto.OFPP_FLOOD and ip_pkt is not None:
            match_kwargs = {
                "in_port": in_port,
                "eth_type": ether_types.ETH_TYPE_IP,
                "ipv4_src": ip_pkt.src,
                "ipv4_dst": ip_pkt.dst,
                "ip_proto": ip_pkt.proto,
            }

            # Scelta architetturale: matching a livello L3 (ipv4_src, ipv4_dst,
            # ip_proto) senza porte di trasporto. Questo riduce l'overhead sul
            # control plane: in presenza di sorgenti che variano dinamicamente le
            # porte L4, un match a 5-tuple genererebbe un table-miss per ogni porta,
            # saturando la CPU del controllore. Con il match a livello IP il traffico
            # tra due host e' aggregato in un'unica entry. Di conseguenza le porte
            # non sono significative come feature: il modello opera sulle metriche
            # volumetriche e aggregate verso il server protetto.
            match = parser.OFPMatch(**match_kwargs)
            self.add_flow(datapath, priority=10, match=match, actions=actions, idle_timeout=10)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)

    def _monitor(self):
        while True:
            for datapath in list(self.datapaths.values()):
                self.request_stats(datapath)
            hub.sleep(2)

    def request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    def _get_match_value(self, match, key, default=None):
        try:
            return match.get(key, default)
        except Exception:
            return default

    def _flow_to_basic_dict(self, stat):
        match = stat.match

        src_ip = self._get_match_value(match, "ipv4_src")
        dst_ip = self._get_match_value(match, "ipv4_dst")

        if not src_ip or not dst_ip:
            return None

        ip_proto = int(self._get_match_value(match, "ip_proto", 0) or 0)

        src_port = 0
        dst_port = 0

        if ip_proto == 6:
            src_port = int(self._get_match_value(match, "tcp_src", 0) or 0)
            dst_port = int(self._get_match_value(match, "tcp_dst", 0) or 0)

        elif ip_proto == 17:
            src_port = int(self._get_match_value(match, "udp_src", 0) or 0)
            dst_port = int(self._get_match_value(match, "udp_dst", 0) or 0)

        duration_sec = float(getattr(stat, "duration_sec", 0) or 0)
        duration_nsec = float(getattr(stat, "duration_nsec", 0) or 0)
        duration = duration_sec + duration_nsec / 1_000_000_000

        packet_count = float(stat.packet_count)
        byte_count = float(stat.byte_count)

        key = str(match)
        prev_packet_count, prev_byte_count, prev_time = self.prev_stats.get(
            key,
            (packet_count, byte_count, time.time())
        )

        now = time.time()
        delta_time = max(now - prev_time, 0.001)

        delta_packets = max(packet_count - prev_packet_count, 0.0)
        delta_bytes = max(byte_count - prev_byte_count, 0.0)

        packet_rate = delta_packets / delta_time
        byte_rate = delta_bytes / delta_time

        avg_packet_size = byte_count / packet_count if packet_count > 0 else 0.0

        self.prev_stats[key] = (packet_count, byte_count, now)

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "ip_proto": float(ip_proto),
            "src_port": float(src_port),
            "dst_port": float(dst_port),
            "packet_count": packet_count,
            "byte_count": byte_count,
            "duration_sec": float(duration),
            "delta_packets": float(delta_packets),
            "delta_bytes": float(delta_bytes),
            "packet_rate": float(packet_rate),
            "byte_rate": float(byte_rate),
            "avg_packet_size": float(avg_packet_size),
        }

    def _build_feature_vector(self, flow, aggregate):
        dst_total_packet_rate = float(aggregate["total_packet_rate"])
        dst_unique_src_count = float(len(aggregate["sources"]))
        packet_rate = float(flow["packet_rate"])
        ip_proto = int(flow["ip_proto"])

        values = {
            "ip_proto": flow["ip_proto"],
            "src_port": flow["src_port"],
            "dst_port": flow["dst_port"],
            "packet_count": flow["packet_count"],
            "byte_count": flow["byte_count"],
            "duration_sec": flow["duration_sec"],
            "delta_packets": flow["delta_packets"],
            "delta_bytes": flow["delta_bytes"],
            "packet_rate": flow["packet_rate"],
            "byte_rate": flow["byte_rate"],
            "avg_packet_size": flow["avg_packet_size"],

            "dst_unique_src_count": dst_unique_src_count,
            "dst_total_packet_rate": dst_total_packet_rate,
            "dst_total_byte_rate": float(aggregate["total_byte_rate"]),
            "dst_active_flow_count": float(aggregate["active_flow_count"]),

            # Feature derivate, calcolate in modo identico alla fase di addestramento.
            "is_tcp": 1.0 if ip_proto == 6 else 0.0,
            "is_udp": 1.0 if ip_proto == 17 else 0.0,
            "flow_to_dst_ratio": packet_rate / (dst_total_packet_rate + 1.0),
            "pps_per_source": dst_total_packet_rate / (dst_unique_src_count + 1.0),
        }

        return pd.DataFrame([[float(values.get(col, 0.0)) for col in self.feature_columns]], columns=self.feature_columns)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        datapath = ev.msg.datapath

        current_flows = []

        for stat in ev.msg.body:
            if stat.priority == 0:
                continue

            flow = self._flow_to_basic_dict(stat)
            if flow is None:
                continue

            current_flows.append(flow)

        dst_aggregates = {}

        for flow in current_flows:
            dst_ip = flow["dst_ip"]

            if dst_ip not in dst_aggregates:
                dst_aggregates[dst_ip] = {
                    "sources": set(),
                    "total_packet_rate": 0.0,
                    "total_byte_rate": 0.0,
                    "active_flow_count": 0,
                }

            dst_aggregates[dst_ip]["sources"].add(flow["src_ip"])
            dst_aggregates[dst_ip]["total_packet_rate"] += flow["packet_rate"]
            dst_aggregates[dst_ip]["total_byte_rate"] += flow["byte_rate"]
            dst_aggregates[dst_ip]["active_flow_count"] += 1

        for flow in current_flows:
            src_ip = flow["src_ip"]
            dst_ip = flow["dst_ip"]
            ip_proto = int(flow["ip_proto"])

            aggregate = dst_aggregates.get(dst_ip, {
                "sources": set(),
                "total_packet_rate": 0.0,
                "total_byte_rate": 0.0,
                "active_flow_count": 0,
            })

            X = self._build_feature_vector(flow, aggregate)

            attack_probability = float(self.model.predict_proba(X)[0][1])
            # Sono valutati solo i flussi attivi (rate non nullo); niente vincolo di
            # protocollo: la classificazione si applica sia a TCP sia a UDP.
            MIN_FLOW_PPS_FOR_ML = 1.0
            ml_pred = (
                flow["packet_rate"] >= MIN_FLOW_PPS_FOR_ML
                and attack_probability >= self.threshold
            )

            dst_unique_src_count = len(aggregate["sources"])
            dst_total_packet_rate = aggregate["total_packet_rate"]
            dst_total_byte_rate = aggregate["total_byte_rate"]
            dst_active_flow_count = aggregate["active_flow_count"]

            # Le condizioni aggregate verso il server protetto sono calcolate a fini di
            # logging e analisi; non concorrono alla decisione, affidata al modello ML.
            aggregate_context = (
                dst_ip == PROTECTED_SERVER_IP
                and dst_unique_src_count >= AGG_MIN_SOURCES
                and dst_total_packet_rate >= AGG_MIN_PACKET_RATE
                and dst_active_flow_count >= AGG_MIN_ACTIVE_FLOWS
            )

            # Decisione affidata al classificatore Random Forest.
            # I falsi positivi transitori sono mitigati dalla conferma su rilevazioni
            # consecutive (SUSPICIOUS_LIMIT), non da soglie che scavalcano il modello.
            
            final_pred = ml_pred

            self.logger.info(
                "Flow %s -> %s proto=%s pps=%.2f bps=%.2f "
                "src_to_dst=%s dst_total_pps=%.2f dst_total_bps=%.2f active_flows=%s "
                "prob=%.3f soglia=%.2f ml=%s agg=%s final=%s",
                src_ip,
                dst_ip,
                ip_proto,
                flow["packet_rate"],
                flow["byte_rate"],
                dst_unique_src_count,
                dst_total_packet_rate,
                dst_total_byte_rate,
                dst_active_flow_count,
                attack_probability,
                self.threshold,
                int(ml_pred),
                int(aggregate_context),
                int(final_pred),
            )

            pair_key = (src_ip, dst_ip)

            if final_pred:
                self.suspicious_counts[pair_key] = self.suspicious_counts.get(pair_key, 0) + 1

                self.logger.warning(
                    "Traffico sospetto %s -> %s: conteggio %s/%s",
                    src_ip,
                    dst_ip,
                    self.suspicious_counts[pair_key],
                    SUSPICIOUS_LIMIT
                )

                if self.suspicious_counts[pair_key] >= SUSPICIOUS_LIMIT:
                    self.add_drop_flow(datapath, src_ip, dst_ip)

            else:
                self.suspicious_counts[pair_key] = 0
