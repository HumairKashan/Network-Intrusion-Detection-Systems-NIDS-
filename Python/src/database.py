from pymongo import MongoClient
from datetime import datetime
from utils import log_success, log_warning, log_error


class DatabaseManager:
    def __init__(self, host="localhost", port=27017, db_name="NIDS"):
        self.db = None
        try:
            self.client = MongoClient(host, port, serverSelectionTimeoutMS=2000)
            self.client.server_info()
            self.db = self.client[db_name]
            log_success(f"Successfully connected to MongoDB: {db_name}")
        except Exception as e:
            log_error(f"DATABASE CONNECTION FAILED: {e}")

    def _sanitize_votes(self, votes: dict) -> dict:
        """
        MongoDB cannot encode numpy scalar types (np.bool_, np.float32, etc.)
        Convert everything to plain Python types.
        """
        if not isinstance(votes, dict):
            return {}

        clean = {}
        for k, v in votes.items():
            # numpy.bool_ -> bool
            if hasattr(v, "item"):
                try:
                    v = v.item()
                except Exception:
                    pass

            # Ensure final types are Mongo-friendly
            if isinstance(v, (bool, int, float, str)) or v is None:
                clean[k] = v
            else:
                clean[k] = str(v)

        return clean

    def log_packet(self, packet_data: dict):
        if self.db is None:
            return None
        try:
            packet_data["recorded_at"] = datetime.now()
            result = self.db.packets.insert_one(packet_data)
            return result.inserted_id
        except Exception as e:
            log_error(f"Failed to log packet: {e}")
            return None

    def log_detection(self, packet_data: dict, is_attack: bool, confidence: float, votes: dict, packet_id=None):
        if self.db is None:
            return None

        votes_clean = self._sanitize_votes(votes)

        doc = {
            "timestamp": datetime.now(),
            "source_ip": packet_data.get("src_ip"),
            "dest_ip": packet_data.get("dst_ip"),
            "protocol": packet_data.get("protocol"),
            "src_port": packet_data.get("src_port"),
            "dst_port": packet_data.get("dst_port"),
            "is_attack": bool(is_attack),
            "confidence": float(confidence),
            "votes": votes_clean,
            "packet_ref": packet_id,
        }

        try:
            result = self.db.detections.insert_one(doc)
            return result.inserted_id
        except Exception as e:
            log_error(f"Failed to save detection: {e}")
            return None

    def log_alert(self, packet_data: dict, confidence: float, votes: dict, packet_id=None):
        if self.db is None:
            return None

        votes_clean = self._sanitize_votes(votes)

        alert_doc = {
            "timestamp": datetime.now(),
            "source_ip": packet_data.get("src_ip"),
            "dest_ip": packet_data.get("dst_ip"),
            "protocol": packet_data.get("protocol"),
            "src_port": packet_data.get("src_port"),
            "dst_port": packet_data.get("dst_port"),
            "confidence": float(confidence),
            "votes": votes_clean,
            "packet_ref": packet_id,
        }

        try:
            result = self.db.alerts.insert_one(alert_doc)
            log_warning(f"ALERT SAVED: {packet_data.get('src_ip')} -> {packet_data.get('dst_ip')}")
            return result.inserted_id
        except Exception as e:
            log_error(f"Failed to save alert: {e}")
            return None
