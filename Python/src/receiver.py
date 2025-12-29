import socket
import json
import base64
import time
from collections import deque

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP

from detector import AnomalyDetector
from database import DatabaseManager
from utils import log_message, log_success, log_warning, log_error


def _infer_service(dst_port: int, proto: str) -> str:
    """
    Very small heuristic to approximate UNSW-NB15 'service' field.
    This is NOT perfect, but gives stable categories for common ports.
    """
    if proto.upper() not in ("TCP", "UDP"):
        return "other"

    port_map = {
        80: "http",
        443: "http",
        21: "ftp",
        20: "ftp-data",
        22: "ssh",
        25: "smtp",
        53: "dns",
        110: "pop3",
        143: "imap",
        123: "ntp",
        161: "snmp",
        389: "ldap",
        445: "smb",
        3306: "mysql",
        3389: "rdp",
        8080: "http",
    }
    return port_map.get(int(dst_port or 0), "other")


def _infer_state(proto: str, pkt) -> str:
    """
    Approximate UNSW-NB15 'state'.
    If you have real TCP flags/handshake tracking later, swap this out.
    """
    p = (proto or "").upper()
    if p == "TCP":
        # If Scapy parsed TCP flags, we can slightly refine.
        try:
            if pkt and pkt.haslayer(TCP):
                flags = int(pkt[TCP].flags)
                # SYN only
                if flags == 0x02:
                    return "SYN"
                # SYN-ACK
                if flags == 0x12:
                    return "SYNACK"
                # RST
                if flags & 0x04:
                    return "RST"
                # FIN
                if flags & 0x01:
                    return "FIN"
        except Exception:
            pass
        return "CON"
    if p == "UDP":
        return "INT"
    if p == "ICMP":
        return "ECO"
    return "UNK"


class FlowWindow:
    """
    Small sliding window counters to approximate some ct_* features.
    This is an approximation (not an exact UNSW-NB15 generator),
    but it's consistent and avoids "missing feature" chaos.
    """

    def __init__(self, maxlen=2000):
        self.maxlen = maxlen
        self.recent_src = deque(maxlen=maxlen)
        self.recent_dst = deque(maxlen=maxlen)
        self.recent_srv = deque(maxlen=maxlen)        # (dst_ip, dst_port)
        self.recent_state = deque(maxlen=maxlen)      # state string
        self.recent_dst_sport = deque(maxlen=maxlen)  # (dst_ip, src_port)
        self.recent_src_dport = deque(maxlen=maxlen)  # (src_ip, dst_port)
        self.recent_dst_src = deque(maxlen=maxlen)    # (dst_ip, src_ip)

    def push(self, src, dst, srv, state, src_port, dst_port):
        self.recent_src.append(src)
        self.recent_dst.append(dst)
        self.recent_srv.append(srv)
        self.recent_state.append(state)
        self.recent_dst_sport.append((dst, src_port))
        self.recent_src_dport.append((src, dst_port))
        self.recent_dst_src.append((dst, src))

    def ct_src_ltm(self, src):
        return sum(1 for x in self.recent_src if x == src)

    def ct_dst_ltm(self, dst):
        return sum(1 for x in self.recent_dst if x == dst)

    def ct_srv_dst(self, srv):
        return sum(1 for x in self.recent_srv if x == srv)

    def ct_state_ttl(self, state):
        return sum(1 for x in self.recent_state if x == state)

    def ct_dst_sport_ltm(self, dst, src_port):
        return sum(1 for x in self.recent_dst_sport if x == (dst, src_port))

    def ct_src_dport_ltm(self, src, dst_port):
        return sum(1 for x in self.recent_src_dport if x == (src, dst_port))

    def ct_dst_src_ltm(self, dst, src):
        return sum(1 for x in self.recent_dst_src if x == (dst, src))


class NIDSReceiver:
    def __init__(self, host="127.0.0.1", port=8080):
        self.host = host
        self.port = port

        # DB is independent of detector. Keep these separated.
        self.db = DatabaseManager()

        # IMPORTANT FIX:
        # AnomalyDetector expects model_dir (string path) or None.
        # Passing DatabaseManager here is what caused:
        # "expected str, bytes or os.PathLike object, not DatabaseManager"
        self.detector = AnomalyDetector()

        self.flow_window = FlowWindow(maxlen=2000)

        self.packet_count = 0
        self.last_log_time = time.time()

    def _decode_packet_bytes(self, packet_b64: str):
        try:
            return base64.b64decode(packet_b64)
        except Exception as e:
            log_error(f"Failed to decode base64 payload: {e}")
            return None

    def _build_features(self, msg: dict, pkt):
        """
        Build a feature dict that tries to align with UNSW-NB15-style features
        (and your feature_meta.json contract).
        Missing fields are filled with safe defaults.
        """
        src_ip = msg.get("src_ip") or ""
        dst_ip = msg.get("dst_ip") or ""
        proto = msg.get("protocol") or ""
        src_port = int(msg.get("src_port") or 0)
        dst_port = int(msg.get("dst_port") or 0)
        length = float(msg.get("length") or 0)

        # duration / bytes (Rust provides defaults)
        dur = float(msg.get("duration") or 0.0)
        sbytes = float(msg.get("src_bytes") or msg.get("sbytes") or length or 0.0)
        dbytes = float(msg.get("dst_bytes") or msg.get("dbytes") or 0.0)

        # ttl
        sttl = 0.0
        if pkt and pkt.haslayer(IP):
            try:
                sttl = float(pkt[IP].ttl)
            except Exception:
                sttl = 0.0

        # Approximate state/service
        state = _infer_state(proto, pkt)
        service = _infer_service(dst_port, proto)

        # Maintain sliding-window counts
        srv = (dst_ip, dst_port)
        self.flow_window.push(src_ip, dst_ip, srv, state, src_port, dst_port)

        feats = {
            # Common UNSW-ish fields
            "proto": str(proto).lower(),
            "protocol": str(proto),           # some contracts use 'protocol'
            "state": str(state).lower(),
            "service": str(service).lower(),

            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": float(src_port),
            "dst_port": float(dst_port),

            "dur": float(dur),
            "length": float(length),

            # UNSW names
            "sbytes": float(sbytes),
            "dbytes": float(dbytes),
            "sttl": float(sttl),

            # Window-derived ct_* approximations
            "ct_src_ltm": float(self.flow_window.ct_src_ltm(src_ip)),
            "ct_dst_ltm": float(self.flow_window.ct_dst_ltm(dst_ip)),
            "ct_srv_dst": float(self.flow_window.ct_srv_dst(srv)),
            "ct_state_ttl": float(self.flow_window.ct_state_ttl(state)),
            "ct_dst_sport_ltm": float(self.flow_window.ct_dst_sport_ltm(dst_ip, src_port)),
            "ct_src_dport_ltm": float(self.flow_window.ct_src_dport_ltm(src_ip, dst_port)),
            "ct_dst_src_ltm": float(self.flow_window.ct_dst_src_ltm(dst_ip, src_ip)),
        }

        # Optional rates (placeholders if your contract includes them)
        # If you later compute these accurately, replace.
        feats.setdefault("Sload", 0.0)
        feats.setdefault("Dload", 0.0)
        feats.setdefault("Sintpkt", 0.0)
        feats.setdefault("tcprtt", 0.0)
        feats.setdefault("smeansz", 0.0)
        feats.setdefault("dmeansz", 0.0)

        return feats

    def process_line(self, line: str):
        """
        One JSON line from Rust.
        """
        try:
            msg = json.loads(line)
        except Exception as e:
            log_error(f"Invalid JSON from Rust: {e} | line={line[:200]}")
            return

        # Rust sends raw_data (base64). Also accept older keys for flexibility.
        data_b64 = (
            msg.get("raw_data")
            or msg.get("data")
            or msg.get("packet")
            or msg.get("payload")
        )

        if not data_b64:
            log_warning(f"Received JSON without packet data keys. keys={list(msg.keys())}")
            return

        raw = self._decode_packet_bytes(str(data_b64))
        if raw is None:
            return

        self.packet_count += 1
        now = time.time()
        if now - self.last_log_time >= 2:
            log_message(f"[PY] receiving... packet_count={self.packet_count}")
            self.last_log_time = now

        # Try to parse a scapy packet (optional)
        pkt = None
        try:
            pkt = Ether(raw)
        except Exception:
            pkt = None

        # 1) Log packet to MongoDB
        packet_id = None
        try:
            # Store a compact copy (do not store full raw if you don't want).
            packet_doc = {
                "timestamp": msg.get("timestamp"),
                "protocol": msg.get("protocol"),
                "src_ip": msg.get("src_ip"),
                "dst_ip": msg.get("dst_ip"),
                "src_port": msg.get("src_port"),
                "dst_port": msg.get("dst_port"),
                "length": msg.get("length"),
                # Store raw as base64 string (Mongo can store it)
                "raw_data": data_b64,
            }
            packet_id = self.db.log_packet(packet_doc)
        except Exception as e:
            log_error(f"Failed to log packet to DB: {e}")

        # 2) Feature extraction + ML detection
        try:
            feats = self._build_features(msg, pkt)
            is_attack, confidence, votes = self.detector.detect(feats)
        except Exception as e:
            log_error(f"Detection failed: {e}")
            return

        # 3) Log detection + optional alert
        try:
            self.db.log_detection(
                packet_data=msg,
                is_attack=is_attack,
                confidence=confidence,
                votes=votes,
                packet_id=packet_id,
            )

            if is_attack and confidence >= 0.5:
                self.db.log_alert(
                    packet_data=msg,
                    confidence=confidence,
                    votes=votes,
                    packet_id=packet_id,
                )
        except Exception as e:
            log_error(f"DB logging failed: {e}")

    def start_listening(self):
        log_message(f"Starting receiver on {self.host}:{self.port} ...")
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(1)
        log_success(f"Listening on {self.host}:{self.port}")

        while True:
            conn, addr = server_socket.accept()
            print("[PY] accepted:", addr, flush=True)
            log_success(f"Connection from {addr}")

            buffer = b""
            last_heartbeat = time.time()
            received_lines = 0

            with conn:
                conn.settimeout(1.0)

                while True:
                    try:
                        chunk = conn.recv(65535)
                    except socket.timeout:
                        if time.time() - last_heartbeat >= 5:
                            log_message(f"[PY] heartbeat: connected, received_lines={received_lines}")
                            last_heartbeat = time.time()
                        continue

                    if not chunk:
                        log_warning("Rust sniffer disconnected.")
                        break

                    buffer += chunk

                    while b"\n" in buffer:
                        line_bytes, buffer = buffer.split(b"\n", 1)
                        line = line_bytes.decode("utf-8", errors="ignore").strip()
                        if not line:
                            continue
                        received_lines += 1
                        self.process_line(line)

                tail = buffer.decode("utf-8", errors="ignore").strip()
                if tail:
                    received_lines += 1
                    self.process_line(tail)
