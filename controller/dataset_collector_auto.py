from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
from ryu.lib.packet import tcp

import csv
import os
import time


CSV_PATH = "dataset/dataset_v8_training.csv"
LABEL_FILE = "/tmp/current_label.txt"


def read_label():
    """Legge etichetta e sessione dal file di sincronizzazione. Restituisce (None, None) durante gli intervalli di transizione (nessun vettore attivo)."""
    try:
        with open(LABEL_FILE) as f:
            c = f.read().strip()
        if ";" in c:
            l, ss = c.split(";", 1)
            return int(l), ss.strip()
        return int(c), "default"
    except Exception:
        return None, None

POLL_INTERVAL = 2

PROTECTED_SERVER_IP = "10.0.0.4"


class DatasetCollectorV8(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DatasetCollectorV8, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.prev_stats = {}
        self.mac_to_port = {}

        os.makedirs(os.path.dirname(CSV_PATH), exist_ok=True)

        self.fieldnames = [
            "timestamp",
            "session_id",
            "dpid",
            "src_ip",
            "dst_ip",
            "ip_proto",
            "src_port",
            "dst_port",
            "packet_count",
            "byte_count",
            "duration_sec",
            "delta_packets",
            "delta_bytes",
            "packet_rate",
            "byte_rate",
            "avg_packet_size",
            "dst_unique_src_count",
            "dst_total_packet_rate",
            "dst_total_byte_rate",
            "dst_active_flow_count",
            "label",
        ]

        if not os.path.exists(CSV_PATH):
            with open(CSV_PATH, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=self.fieldnames)
                writer.writeheader()

        self._cur_label = None
        self._cur_session = "default"
        self.monitor_thread = hub.spawn(self._monitor)

        self.logger.info("Dataset collector V8 avviato")
        self.logger.info("CSV: %s", CSV_PATH)
        self.logger.info("Etichetta dinamica da %s", LABEL_FILE)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        self.logger.info("Switch registrato: %s", datapath.id)

    def add_flow(self, datapath, priority, match, actions):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
        )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        self.datapaths[datapath.id] = datapath


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            return

        dst = eth.dst
        src = eth.src

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        udp_pkt = pkt.get_protocol(udp.udp)
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        if out_port != ofproto.OFPP_FLOOD and ip_pkt:
            if udp_pkt:
                match = parser.OFPMatch(
                    eth_type=0x0800,
                    ipv4_src=ip_pkt.src,
                    ipv4_dst=ip_pkt.dst,
                    ip_proto=17,
                    udp_src=udp_pkt.src_port,
                    udp_dst=udp_pkt.dst_port
                )
                self.add_flow(datapath, 10, match, actions)

            elif tcp_pkt:
                match = parser.OFPMatch(
                    eth_type=0x0800,
                    ipv4_src=ip_pkt.src,
                    ipv4_dst=ip_pkt.dst,
                    ip_proto=6,
                    tcp_src=tcp_pkt.src_port,
                    tcp_dst=tcp_pkt.dst_port
                )
                self.add_flow(datapath, 10, match, actions)

            else:
                match = parser.OFPMatch(
                    eth_type=0x0800,
                    ipv4_src=ip_pkt.src,
                    ipv4_dst=ip_pkt.dst,
                    ip_proto=ip_pkt.proto
                )
                self.add_flow(datapath, 5, match, actions)

        elif out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(datapath, 1, match, actions)

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
            for dp in list(self.datapaths.values()):
                self._request_stats(dp)
            hub.sleep(POLL_INTERVAL)

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        # Lettura dell'etichetta corrente; durante gli intervalli di transizione non si registra
        lab, sess = read_label()
        if lab is None:
            return
        self._cur_label = lab
        self._cur_session = sess

        body = ev.msg.body
        dpid = ev.msg.datapath.id

        current_flows = []
        now = time.time()

        for stat in body:
            match = stat.match

            src_ip = match.get("ipv4_src")
            dst_ip = match.get("ipv4_dst")

            if not src_ip or not dst_ip:
                continue

            ip_proto = int(match.get("ip_proto", 0))
            src_port = int(match.get("udp_src", match.get("tcp_src", 0)) or 0)
            dst_port = int(match.get("udp_dst", match.get("tcp_dst", 0)) or 0)

            packet_count = int(stat.packet_count)
            byte_count = int(stat.byte_count)
            duration_sec = float(stat.duration_sec) + float(stat.duration_nsec) / 1e9

            key = (dpid, src_ip, dst_ip, ip_proto, src_port, dst_port)
            prev_packets, prev_bytes, prev_time = self.prev_stats.get(
                key,
                (packet_count, byte_count, now)
            )

            elapsed = max(now - prev_time, 0.001)

            delta_packets = max(packet_count - prev_packets, 0)
            delta_bytes = max(byte_count - prev_bytes, 0)

            packet_rate = delta_packets / elapsed
            byte_rate = delta_bytes / elapsed

            avg_packet_size = byte_count / packet_count if packet_count > 0 else 0.0

            self.prev_stats[key] = (packet_count, byte_count, now)

            flow = {
                "timestamp": now,
                "session_id": self._cur_session,
                "dpid": dpid,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "ip_proto": ip_proto,
                "src_port": src_port,
                "dst_port": dst_port,
                "packet_count": packet_count,
                "byte_count": byte_count,
                "duration_sec": duration_sec,
                "delta_packets": delta_packets,
                "delta_bytes": delta_bytes,
                "packet_rate": packet_rate,
                "byte_rate": byte_rate,
                "avg_packet_size": avg_packet_size,
            }

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

        rows = []

        for flow in current_flows:
            aggregate = dst_aggregates.get(flow["dst_ip"], {
                "sources": set(),
                "total_packet_rate": 0.0,
                "total_byte_rate": 0.0,
                "active_flow_count": 0,
            })

            row = dict(flow)
            row["dst_unique_src_count"] = len(aggregate["sources"])
            row["dst_total_packet_rate"] = aggregate["total_packet_rate"]
            row["dst_total_byte_rate"] = aggregate["total_byte_rate"]
            row["dst_active_flow_count"] = aggregate["active_flow_count"]
            row["label"] = self._cur_label

            rows.append(row)

        if rows:
            with open(CSV_PATH, "a", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=self.fieldnames)
                writer.writerows(rows)

            self.logger.info("Salvate %s righe | session=%s label=%s",
                             len(rows), self._cur_session, self._cur_label)
