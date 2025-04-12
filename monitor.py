import scapy.all as scapy
from collections import defaultdict
import pandas as pd
from sklearn.ensemble import IsolationForest

class NetworkAnalyzer:
    def __init__(self):
        self.traffic_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'protocols': defaultdict(int),
            'ports': defaultdict(int)
        })
        self.anomaly_model = IsolationForest(contamination=0.05)
        self.baseline_established = False
        
    def analyze_packet(self, packet):
        """Analyze a single packet and update traffic statistics"""
        if packet.haslayer(scapy.IP):
            # Extract source and destination IP
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            
            # Update statistics for this IP pair
            ip_pair = f"{src_ip}_{dst_ip}"
            self.traffic_stats[ip_pair]['packet_count'] += 1
            self.traffic_stats[ip_pair]['byte_count'] += len(packet)
            
            # Track protocol
            if packet.haslayer(scapy.TCP):
                self.traffic_stats[ip_pair]['protocols']['TCP'] += 1
                sport, dport = packet[scapy.TCP].sport, packet[scapy.TCP].dport
                self.traffic_stats[ip_pair]['ports'][f"TCP_{sport}"] += 1
                self.traffic_stats[ip_pair]['ports'][f"TCP_{dport}"] += 1
            elif packet.haslayer(scapy.UDP):
                self.traffic_stats[ip_pair]['protocols']['UDP'] += 1
                sport, dport = packet[scapy.UDP].sport, packet[scapy.UDP].dport
                self.traffic_stats[ip_pair]['ports'][f"UDP_{sport}"] += 1
                self.traffic_stats[ip_pair]['ports'][f"UDP_{dport}"] += 1
            
            # Check for anomalies if baseline is established
            if self.baseline_established:
                return self.detect_anomalies(ip_pair)
        
        return None
    
    def establish_baseline(self):
        """Train the anomaly detection model on current traffic patterns"""
        # Convert traffic stats to features
        features = self._extract_features()
        
        # Train the model
        if len(features) > 10:  # Need enough data points
            self.anomaly_model.fit(features)
            self.baseline_established = True
            return True
        return False
    
    def detect_anomalies(self, ip_pair):
        """Detect if traffic for this IP pair is anomalous"""
        # Extract features for this IP pair
        features = self._extract_features(ip_pair)
        
        # Predict anomaly (-1 for anomalies, 1 for normal)
        if len(features) > 0:
            prediction = self.anomaly_model.predict(features)
            if prediction[0] == -1:
                return {
                    'ip_pair': ip_pair,
                    'severity': 'high',
                    'reason': 'Anomalous traffic pattern detected',
                    'details': self.traffic_stats[ip_pair]
                }
        return None
    
    def _extract_features(self, specific_ip_pair=None):
        """Convert traffic statistics to numerical features for anomaly detection"""
        features = []
        
        if specific_ip_pair:
            # Extract features for a specific IP pair
            stats = self.traffic_stats[specific_ip_pair]
            features.append([
                stats['packet_count'],
                stats['byte_count'],
                len(stats['protocols']),
                len(stats['ports']),
                stats['protocols'].get('TCP', 0),
                stats['protocols'].get('UDP', 0)
            ])
        else:
            # Extract features for all IP pairs
            for ip_pair, stats in self.traffic_stats.items():
                features.append([
                    stats['packet_count'],
                    stats['byte_count'],
                    len(stats['protocols']),
                    len(stats['ports']),
                    stats['protocols'].get('TCP', 0),
                    stats['protocols'].get('UDP', 0)
                ])
        
        return pd.DataFrame(features)