#!/usr/bin/env python3
from pymongo import MongoClient
from datetime import datetime, timedelta
import sys

"""
NIDS Analytics - Query MongoDB for detection statistics
"""

class NIDSAnalytics:
    def __init__(self, host="localhost", port=27017, db_name="NIDS"):
        try:
            self.client = MongoClient(host, port, serverSelectionTimeoutMS=2000)
            self.db = self.client[db_name]
            print(f"✓ Connected to MongoDB: {db_name}\n")
        except Exception as e:
            print(f"✗ Database connection failed: {e}")
            sys.exit(1)

    def attack_rate(self, minutes=None):
        """Calculate attack detection rate."""
        query = {}
        if minutes:
            cutoff = datetime.now() - timedelta(minutes=minutes)
            query = {"timestamp": {"$gte": cutoff}}

        total = self.db.detections.count_documents(query)
        attacks = self.db.detections.count_documents({**query, "is_attack": True})

        rate = (attacks / total * 100) if total > 0 else 0

        print("=" * 60)
        print(f"ATTACK RATE {'(last ' + str(minutes) + ' min)' if minutes else '(all time)'}")
        print("=" * 60)
        print(f"Total Detections:  {total:,}")
        print(f"Attacks Detected:  {attacks:,}")
        print(f"Attack Rate:       {rate:.2f}%")
        print()

    def confidence_distribution(self, minutes=None):
        """Show confidence score breakdown."""
        query = {}
        if minutes:
            cutoff = datetime.now() - timedelta(minutes=minutes)
            query = {"timestamp": {"$gte": cutoff}}

        pipeline = [
            {"$match": query},
            {"$group": {"_id": "$confidence", "count": {"$sum": 1}}},
            {"$sort": {"_id": 1}}
        ]

        results = list(self.db.detections.aggregate(pipeline))

        # Bucket into 0.33, 0.66, 1.0
        buckets = {0.33: 0, 0.66: 0, 1.0: 0}
        for r in results:
            conf = r.get("_id")
            count = int(r.get("count", 0))

            # Skip weird/null confidence values safely (from version 2)
            if conf is None:
                continue

            try:
                conf_val = float(conf)
            except Exception:
                continue

            if conf_val <= 0.4:
                buckets[0.33] += count
            elif conf_val <= 0.7:
                buckets[0.66] += count
            else:
                buckets[1.0] += count

        total = sum(buckets.values())

        print("=" * 60)
        print("CONFIDENCE DISTRIBUTION")
        print("=" * 60)
        for conf, count in sorted(buckets.items()):
            pct = (count / total * 100) if total > 0 else 0
            bar = "█" * int(pct / 2)
            print(f"{conf:.2f}: {count:6,} ({pct:5.1f}%) {bar}")
        print()

    def alerts_per_minute(self, minutes=60):
        """Show alert rate over time."""
        cutoff = datetime.now() - timedelta(minutes=minutes)

        pipeline = [
            {"$match": {"timestamp": {"$gte": cutoff}}},
            {"$group": {
                "_id": {
                    "$dateToString": {
                        "format": "%Y-%m-%d %H:%M",
                        "date": "$timestamp"
                    }
                },
                "count": {"$sum": 1}
            }},
            {"$sort": {"_id": 1}}
        ]

        results = list(self.db.alerts.aggregate(pipeline))

        print("=" * 60)
        print(f"ALERTS PER MINUTE (last {minutes} min)")
        print("=" * 60)
        if not results:
            print("No alerts in this time window")
        else:
            for r in results[-20:]:  # Last 20 minutes
                time_str = r.get("_id")
                count = int(r.get("count", 0))
                bar = "█" * min(count, 50)
                print(f"{time_str}: {count:4,} {bar}")
        print()

    def top_sources(self, limit=10, minutes=None):
        """Show top attacking source IPs (robust with $ifNull + defensive null handling)."""
        query = {"is_attack": True}
        if minutes:
            cutoff = datetime.now() - timedelta(minutes=minutes)
            query["timestamp"] = {"$gte": cutoff}

        # BEST: $ifNull from version 1 (efficient single query)
        pipeline = [
            {"$match": query},
            {"$project": {"src": {"$ifNull": ["$source_ip", "$src_ip"]}}},
            {"$group": {"_id": "$src", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": limit}
        ]

        results = list(self.db.detections.aggregate(pipeline))

        print("=" * 60)
        print(f"TOP {limit} ATTACKING SOURCE IPs")
        print("=" * 60)

        if not results:
            print("No attacking sources found")
        else:
            shown = 0
            for r in results:
                ip = r.get("_id")
                if ip is None:  # Defensive from version 2
                    continue
                count = int(r.get("count", 0))

                ip_str = str(ip)
                shown += 1
                print(f"{shown:2}. {ip_str:15s} - {count:6,} detections")
                if shown >= limit:
                    break
        print()

    def top_ports(self, limit=10, minutes=None):
        """Show top targeted destination ports."""
        query = {"is_attack": True}
        if minutes:
            cutoff = datetime.now() - timedelta(minutes=minutes)
            query["timestamp"] = {"$gte": cutoff}

        pipeline = [
            {"$match": query},
            {"$group": {"_id": "$dst_port", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": limit}
        ]

        results = list(self.db.detections.aggregate(pipeline))

        print("=" * 60)
        print(f"TOP {limit} TARGETED PORTS")
        print("=" * 60)

        if not results:
            print("No targeted ports found")
        else:
            shown = 0
            for r in results:
                port = r.get("_id")
                if port is None:  # Defensive from version 2
                    continue
                count = int(r.get("count", 0))

                try:
                    port_int = int(port)
                except Exception:
                    port_int = port

                shown += 1
                print(f"{shown:2}. Port {port_int!s:5} - {count:6,} detections")
                if shown >= limit:
                    break
        print()

    def run_full_report(self, minutes=None):
        """Generate complete analytics report."""
        print("\n" + "=" * 60)
        print(" NIDS DETECTION ANALYTICS REPORT")
        print("=" * 60 + "\n")

        self.attack_rate(minutes)
        self.confidence_distribution(minutes)
        self.alerts_per_minute(60)
        self.top_sources(10, minutes)
        self.top_ports(10, minutes)


def main():
    analytics = NIDSAnalytics()

    print("Choose report type:")
    print("1. Full report (all time)")
    print("2. Full report (last 60 minutes)")
    print("3. Attack rate only")
    print("4. Quick summary")

    choice = input("\nEnter choice (1-4, default=4): ").strip() or "4"

    if choice == "1":
        analytics.run_full_report()
    elif choice == "2":
        analytics.run_full_report(minutes=60)
    elif choice == "3":
        analytics.attack_rate()
    else:  # Quick summary
        analytics.attack_rate(minutes=60)
        analytics.confidence_distribution(minutes=60)
        analytics.top_sources(5, minutes=60)


if __name__ == "__main__":
    main()