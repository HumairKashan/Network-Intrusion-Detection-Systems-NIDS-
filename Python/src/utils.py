from datetime import datetime
import sys

class Colors:
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'

def get_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def log_message(msg):
    """the log info gets displayed here"""
    timestamp = get_timestamp()
    print(f"[{timestamp}] [INFO] {msg}")

def log_success(msg):
    """the log success gets displayed here"""
    timestamp = get_timestamp()
    print(f"[{timestamp}] [SUCCESS] {msg}")

def log_warning(msg):
    """the log warning gets displayed here"""
    timestamp = get_timestamp()
    print(f"[{timestamp}] [WARNING] {msg}")

def log_error(msg):
    """the log error gets displayed here"""
    timestamp = get_timestamp()
    print(f"[{timestamp}] [ERROR] {msg}")

def format_bytes(bytes_val):
    """Format bytes into a readable format that humans can understand"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_val < 1024.0:
            return f"{bytes_val:.2f} {unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.2f} TB"

def format_rate(packets_per_sec):
    """Format packet rate"""
    if packets_per_sec < 1000:
        return f"{packets_per_sec:.2f} pkt/s"
    else:
        return f"{packets_per_sec/1000:.2f} Kpkt/s"

class Statistics:
    """Track detection statistics"""

    def __init__(self):
        self.total_packets = 0
        self.total_attacks = 0
        self.start_time = datetime.now()

    def update(self, is_attack):
        """Update statistics"""
        self.total_packets += 1
        if is_attack:
            self.total_attacks += 1

    def get_attack_rate(self):
        """Calculate attack rate percentage"""
        if self.total_packets == 0:
            return 0.0
        return (self.total_attacks / self.total_packets) * 100

    def get_throughput(self):
        """Calculate packets per second"""
        elapsed = (datetime.now() - self.start_time).total_seconds()
        if elapsed == 0:
            return 0.0
        return self.total_packets / elapsed

    def print_summary(self):
        """Print statistics summary"""
        print("\n" + "=" * 60)
        print("Detection Statistics")
        print("=" * 60)
        print(f"Total Packets:   {self.total_packets}")
        print(f"Attacks Detected: {self.total_attacks}")
        print(f"Attack Rate:     {self.get_attack_rate():.2f}%")
        print(f"Throughput:      {format_rate(self.get_throughput())}")
        elapsed = (datetime.now() - self.start_time).total_seconds()
        print(f"Runtime:         {elapsed:.2f} seconds")
        print("=" * 60)
