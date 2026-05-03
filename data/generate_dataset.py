# data/generate_dataset.py
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
import networkx as nx
import random
from datetime import datetime, timedelta

def generate_cyber_threat_dataset(n_samples=150000):
    """
    Generate a balanced cyber threat dataset with 150,000 samples
    Features inspired by UNSW-NB15, CIC-IDS2017, and custom network features
    """
    np.random.seed(42)
    
    # Define attack types
    attack_types = ['normal', 'dos', 'probe', 'r2l', 'u2r', 'malware', 'phishing', 'ransomware', 'botnet', 'zero-day']
    
    # Network protocol features
    protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS', 'FTP', 'SSH']
    services = ['http', 'smtp', 'ftp', 'ssh', 'dns', 'pop3', 'smtp', 'irc']
    flags = ['SF', 'S0', 'S1', 'S2', 'S3', 'REJ', 'RSTO', 'RSTR']
    
    # Generate features
    data = []
    
    for i in range(n_samples):
        # Determine if this is an attack
        is_attack = random.random() < 0.45  # 45% attacks, 55% normal (balanced)
        
        if not is_attack:
            attack_type = 'normal'
        else:
            attack_type = random.choice([at for at in attack_types if at != 'normal'])
        
        # Generate network features
        duration = abs(np.random.exponential(0.5))  # Connection duration
        protocol = random.choice(protocols)
        service = random.choice(services)
        flag = random.choice(flags)
        
        # Source and destination features
        src_bytes = int(abs(np.random.lognormal(mean=8, sigma=2)))
        dst_bytes = int(abs(np.random.lognormal(mean=7, sigma=2)))
        
        # Attack-specific patterns
        if attack_type == 'normal':
            # Normal traffic patterns
            src_bytes = min(src_bytes, 100000)
            dst_bytes = min(dst_bytes, 100000)
            wrong_fragment = random.randint(0, 1)
            urgent = random.randint(0, 1)
            num_failed_logins = random.randint(0, 2)
            logged_in = random.choice([0, 1])
        else:
            # Attack traffic patterns
            if attack_type == 'dos':
                src_bytes = np.random.randint(100000, 1000000)
                wrong_fragment = random.randint(0, 5)
                urgent = random.randint(0, 5)
                num_failed_logins = 0
                logged_in = 0
            elif attack_type == 'probe':
                dst_bytes = np.random.randint(50000, 500000)
                wrong_fragment = random.randint(0, 3)
                urgent = 0
                num_failed_logins = random.randint(0, 3)
                logged_in = random.choice([0, 1])
            elif attack_type == 'r2l':
                src_bytes = np.random.randint(1000, 10000)
                wrong_fragment = 0
                urgent = random.randint(0, 2)
                num_failed_logins = np.random.randint(3, 10)
                logged_in = 0
            elif attack_type == 'u2r':
                src_bytes = np.random.randint(100, 5000)
                wrong_fragment = random.randint(0, 2)
                urgent = random.randint(0, 3)
                num_failed_logins = random.randint(0, 5)
                logged_in = 1
            elif attack_type == 'malware':
                src_bytes = np.random.randint(50000, 300000)
                dst_bytes = np.random.randint(50000, 300000)
                wrong_fragment = random.randint(0, 4)
                urgent = random.randint(0, 4)
                num_failed_logins = random.randint(0, 4)
                logged_in = random.choice([0, 1])
        
        # Additional features
        hot = random.randint(0, 10)
        num_compromised = random.randint(0, 5) if attack_type != 'normal' else 0
        root_shell = 1 if attack_type == 'u2r' and random.random() < 0.3 else 0
        su_attempted = 1 if attack_type == 'u2r' and random.random() < 0.2 else 0
        num_root = random.randint(0, 5) if attack_type == 'u2r' else 0
        num_file_creations = random.randint(0, 10) if attack_type in ['u2r', 'malware'] else 0
        
        # Network graph features (simulated)
        num_connections = np.random.poisson(5) + 1
        avg_packet_size = src_bytes / max(num_connections, 1)
        connection_variance = np.random.uniform(0, 1)
        
        # Threat score (for regression)
        threat_score = 0.0
        if attack_type != 'normal':
            threat_score = random.uniform(0.3, 1.0)
        
        # Timestamp
        base_time = datetime.now() - timedelta(days=random.randint(0, 30))
        timestamp = base_time + timedelta(seconds=random.randint(0, 86400))
        
        data.append({
            'timestamp': timestamp,
            'duration': duration,
            'protocol_type': protocol,
            'service': service,
            'flag': flag,
            'src_bytes': src_bytes,
            'dst_bytes': dst_bytes,
            'wrong_fragment': wrong_fragment,
            'urgent': urgent,
            'hot': hot,
            'num_failed_logins': num_failed_logins,
            'logged_in': logged_in,
            'num_compromised': num_compromised,
            'root_shell': root_shell,
            'su_attempted': su_attempted,
            'num_root': num_root,
            'num_file_creations': num_file_creations,
            'num_connections': num_connections,
            'avg_packet_size': avg_packet_size,
            'connection_variance': connection_variance,
            'attack_type': attack_type,
            'threat_score': threat_score,
            'is_attack': 1 if attack_type != 'normal' else 0
        })
    
    df = pd.DataFrame(data)
    
    # Add some missing values for realism
    for col in ['service', 'flag']:
        df.loc[df.sample(frac=0.01).index, col] = None
    
    # Save to CSV
    df.to_csv('data/cyber_threat_dataset.csv', index=False)
    print(f"Generated dataset with {len(df)} samples")
    print(f"Attack distribution:\n{df['attack_type'].value_counts()}")
    
    return df

if __name__ == "__main__":
    df = generate_cyber_threat_dataset(150000)