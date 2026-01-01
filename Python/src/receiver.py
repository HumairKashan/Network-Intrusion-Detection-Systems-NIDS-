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
        self.detector = AnomalyDetector()
        self.flow_window = FlowWindow(maxlen=2000)

        self.packet_count = 0
        self.last_log_time = time.time()

        # NEW: Robustness tracking
        self.dropped_count = 0
        self.dropped_reasons = {}  # reason -> count
        self.alert_dedup = {}  # (flow_key, protocol, conf_bucket) -> last_timestamp
        self.alert_count = 0

    def _decode_packet_bytes(self, packet_b64: str):
        try:
            return base64.b64decode(packet_b64)
        except Exception as e:
            log_error(f"Failed to decode base64 payload: {e}")
            return None

    def _validate_schema(self, msg: dict) -> tuple:
        """
        Validate required fields EXIST (not that they're truthy).
        Returns (is_valid, reason_if_invalid)
        """
        # Core fields that must exist
        core_required = ["src_ip", "dst_ip", "protocol", "src_port", "dst_port"]
        
        # Check core fields presence
        missing = [k for k in core_required if k not in msg or msg[k] is None]
        
        if missing:
            return False, f"missing_fields:{','.join(missing)}"
        
        # At least ONE payload field must exist (raw_data OR fallback keys)
        payload_keys = ["raw_data", "data", "packet", "payload"]
        has_payload = any(k in msg and msg[k] is not None for k in payload_keys)
        
        if not has_payload:
            return False, "missing_payload:no_raw_data_or_fallbacks"
        
        # Additional sanity checks
        if msg.get("src_ip") == "0.0.0.0" or msg.get("dst_ip") == "0.0.0.0":
            return False, "invalid_ip:0.0.0.0"
        
        # Allow port 0 for ICMP, but check it's an integer
        try:
            int(msg.get("src_port", 0))
            int(msg.get("dst_port", 0))
        except (ValueError, TypeError):
            return False, "invalid_port_type"
        
        return True, ""

    def _check_feature_completeness(self, feats: dict) -> tuple:
        """
        Verify CORE features exist (not all 38, just the critical ones).
        Returns (is_complete, reason_if_incomplete)
        """
        # Only check features we ACTUALLY compute in _build_features()
        core_features = [
            "proto", "state", "service",
            "dur", "sbytes", "dbytes", "sttl",
            "src_port", "dst_port",
            "ct_src_ltm", "ct_dst_ltm", "ct_srv_dst"
        ]
        
        missing = [f for f in core_features if f not in feats]
        
        if len(missing) > 3:  # Allow a few missing, but not most
            return False, f"missing_core_features:{','.join(missing[:5])}"
        
        return True, ""

    def _should_alert(self, msg: dict, confidence: float) -> bool:
        """
        Rate-limit alerts to prevent spam.
        Returns True if should create new alert.
        """
        src_ip = msg.get("src_ip")
        dst_ip = msg.get("dst_ip")
        src_port = msg.get("src_port")
        dst_port = msg.get("dst_port")
        protocol = msg.get("protocol", "").upper()  # Normalize protocol
        
        # Dedup key: flow (with direction) + protocol + confidence bucket
        # Normalize flow direction: sort IPs/ports so (A->B) and (B->A) dedup separately
        if src_ip < dst_ip:
            flow_key = (src_ip, src_port, dst_ip, dst_port)
        else:
            flow_key = (dst_ip, dst_port, src_ip, src_port)
        
        # Confidence bucket (FIXED: explicit thresholds)
        if confidence <= 0.4:
            conf_bucket = 0  # ~0.33
        elif confidence <= 0.7:
            conf_bucket = 1  # ~0.66
        else:
            conf_bucket = 2  # 1.0
        
        # Complete dedup key: flow + protocol + confidence
        dedup_key = (flow_key, protocol, conf_bucket)
        
        now = time.time()
        cooldown = 30  # seconds
        
        if dedup_key in self.alert_dedup:
            last_seen = self.alert_dedup[dedup_key]
            if now - last_seen < cooldown:
                return False  # Too recent, skip
        
        self.alert_dedup[dedup_key] = now
        return True

    def _log_stats(self):
        """Print debug stats every N packets."""
        if self.packet_count % 1000 == 0 and self.packet_count > 0:
            total = self.packet_count + self.dropped_count
            drop_rate = (self.dropped_count / total * 100) if total > 0 else 0
            
            log_message(f"Stats: received={self.packet_count}, dropped={self.dropped_count} ({drop_rate:.1f}%), alerts={self.alert_count}")
            
            if self.dropped_reasons:
                top_reasons = sorted(self.dropped_reasons.items(), key=lambda x: x[1], reverse=True)[:3]
                log_message(f"Top drop reasons: {top_reasons}")

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
        Process one JSON line from Rust with robustness guardrails.
        """
        # Parse JSON
        try:
            msg = json.loads(line)
        except Exception as e:
            log_error(f"Invalid JSON from Rust: {e} | line={line[:200]}")
            return

        # GUARDRAIL 1: Schema validation
        is_valid, reason = self._validate_schema(msg)
        if not is_valid:
            self.dropped_count += 1
            self.dropped_reasons[reason] = self.dropped_reasons.get(reason, 0) + 1
            return

        # Decode packet (RESTORED: fallback keys for backward compatibility)
        data_b64 = (
            msg.get("raw_data")
            or msg.get("data")
            or msg.get("packet")
            or msg.get("payload")
        )

        if not data_b64:
            self.dropped_count += 1
            self.dropped_reasons["no_raw_data"] = self.dropped_reasons.get("no_raw_data", 0) + 1
            return

        raw = self._decode_packet_bytes(str(data_b64))
        if raw is None:
            self.dropped_count += 1
            self.dropped_reasons["decode_failed"] = self.dropped_reasons.get("decode_failed", 0) + 1
            return

        self.packet_count += 1
        now = time.time()
        
        # Original heartbeat logging (keep existing behavior)
        if now - self.last_log_time >= 2:
            log_message(f"[PY] receiving... packet_count={self.packet_count}")
            self.last_log_time = now
        
        # NEW: Periodic stats logging
        self._log_stats()

        # Try to parse a scapy packet (optional)
        pkt = None
        try:
            pkt = Ether(raw)
        except Exception:
            pkt = None

        # 1) Log packet to MongoDB
        packet_id = None
        try:
            packet_doc = {
                "timestamp": msg.get("timestamp"),
                "protocol": msg.get("protocol"),
                "src_ip": msg.get("src_ip"),
                "dst_ip": msg.get("dst_ip"),
                "src_port": msg.get("src_port"),
                "dst_port": msg.get("dst_port"),
                "length": msg.get("length"),
                "raw_data": data_b64,
            }
            packet_id = self.db.log_packet(packet_doc)
        except Exception as e:
            log_error(f"Failed to log packet to DB: {e}")

        # GUARDRAIL 2: Feature extraction with completeness check
        try:
            feats = self._build_features(msg, pkt)
            
            is_complete, reason = self._check_feature_completeness(feats)
            if not is_complete:
                self.dropped_count += 1
                self.dropped_reasons[reason] = self.dropped_reasons.get(reason, 0) + 1
                return
            
            # Detection
            is_attack, confidence, votes = self.detector.detect(feats)
        except Exception as e:
            log_error(f"Detection failed: {e}")
            self.dropped_count += 1
            self.dropped_reasons["detection_error"] = self.dropped_reasons.get("detection_error", 0) + 1
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

            # GUARDRAIL 3: Alert deduplication
            if is_attack and confidence >= 1.0: # changed 0.5 to 1.0 for a temporary fix, might need to adjust later
                if self._should_alert(msg, confidence):
                    self.db.log_alert(
                        packet_data=msg,
                        confidence=confidence,
                        votes=votes,
                        packet_id=packet_id,
                    )
                    self.alert_count += 1
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
                    except Exception as e:  # NEW: Catch connection errors
                        log_error(f"Connection error: {e}")
                        break  # Break inner loop, wait for reconnection

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
            
            # After connection closes, loop back to accept() and wait for Rust to reconnect
            log_message("Waiting for Rust to reconnect...")