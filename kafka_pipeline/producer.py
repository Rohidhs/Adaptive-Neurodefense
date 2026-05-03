# kafka_pipeline/producer.py
from kafka import KafkaProducer
import json
import time
import random
import pandas as pd
from datetime import datetime
import numpy as np

class ThreatDataProducer:
    def __init__(self, bootstrap_servers='localhost:9092'):
        self.producer = KafkaProducer(
            bootstrap_servers=bootstrap_servers,
            value_serializer=lambda v: json.dumps(v).encode('utf-8'),
            acks='all'
        )
        self.topics = ['network_traffic', 'threat_alerts', 'system_logs']
        
    def generate_network_event(self):
        """Generate simulated network event"""
        protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS']
        services = ['http', 'smtp', 'ftp', 'ssh', 'dns']
        flags = ['SF', 'S0', 'S1', 'REJ']
        
        attack_probability = random.random()
        
        event = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': f"192.168.{random.randint(1,255)}.{random.randint(1,255)}",
            'dest_ip': f"10.0.{random.randint(1,255)}.{random.randint(1,255)}",
            'source_port': random.randint(1024, 65535),
            'dest_port': random.choice([80, 443, 22, 25, 53]),
            'protocol': random.choice(protocols),
            'service': random.choice(services),
            'flag': random.choice(flags),
            'src_bytes': random.randint(100, 1000000),
            'dst_bytes': random.randint(100, 500000),
            'duration': random.uniform(0, 60),
            'wrong_fragment': random.randint(0, 5),
            'urgent': random.randint(0, 2),
            'hot': random.randint(0, 10),
            'num_failed_logins': random.randint(0, 5),
            'logged_in': random.choice([0, 1]),
            'is_attack': 1 if attack_probability < 0.3 else 0,
            'attack_type': random.choice(['normal', 'dos', 'probe', 'malware']) if attack_probability < 0.3 else 'normal',
            'threat_score': random.uniform(0, 1) if attack_probability < 0.3 else 0
        }
        
        return event
    
    def start_producing(self, interval=1):
        """Start producing events at regular intervals"""
        print("Starting Kafka Producer...")
        try:
            while True:
                # Generate network event
                event = self.generate_network_event()
                
                # Send to network_traffic topic
                self.producer.send('network_traffic', value=event)
                
                # Send alerts for attacks
                if event['is_attack'] == 1:
                    alert = {
                        'timestamp': event['timestamp'],
                        'source_ip': event['source_ip'],
                        'attack_type': event['attack_type'],
                        'threat_score': event['threat_score'],
                        'action_taken': 'pending',
                        'severity': 'high' if event['threat_score'] > 0.7 else 'medium'
                    }
                    self.producer.send('threat_alerts', value=alert)
                
                # Send system logs
                log = {
                    'timestamp': event['timestamp'],
                    'component': 'network_monitor',
                    'level': 'WARNING' if event['is_attack'] else 'INFO',
                    'message': f"Traffic detected from {event['source_ip']} to {event['dest_ip']}"
                }
                self.producer.send('system_logs', value=log)
                
                print(f"Produced event: {event['source_ip']} -> {event['dest_ip']} | Attack: {event['is_attack']}")
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\nStopping producer...")
        finally:
            self.producer.flush()
            self.producer.close()

if __name__ == "__main__":
    producer = ThreatDataProducer()
    producer.start_producing(interval=0.5)