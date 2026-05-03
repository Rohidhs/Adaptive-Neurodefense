# kafka_pipeline/consumer.py
from kafka import KafkaConsumer
import json
import pickle
import torch
import numpy as np
from datetime import datetime
import pandas as pd
from models.gnn_rl_model import ThreatDetectionModel, RLDefenseAgent

class ThreatDetectionConsumer:
    def __init__(self, bootstrap_servers='localhost:9092'):
        self.consumer = KafkaConsumer(
            'network_traffic',
            bootstrap_servers=bootstrap_servers,
            auto_offset_reset='latest',
            enable_auto_commit=True,
            group_id='threat_detection_group',
            value_deserializer=lambda x: json.loads(x.decode('utf-8'))
        )
        
        # Load trained model
        self.load_models()
        
        # Load preprocessing objects
        with open('models/saved_models/scaler.pkl', 'rb') as f:
            self.scaler = pickle.load(f)
        
        with open('models/saved_models/label_encoder.pkl', 'rb') as f:
            self.label_encoder = pickle.load(f)
        
        with open('models/saved_models/feature_columns.json', 'r') as f:
            import json
            self.feature_columns = json.load(f)
        
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        
        # Initialize RL agent
        self.rl_agent = RLDefenseAgent()
        self.rl_agent.q_network.load_state_dict(
            torch.load('models/saved_models/rl_agent.pth', map_location=self.device)
        )
        self.rl_agent.q_network.eval()
        
        # Statistics
        self.stats = {
            'total_events': 0,
            'threats_detected': 0,
            'false_positives': 0,
            'actions_taken': []
        }
    
    def load_models(self):
        """Load trained threat detection model"""
        self.model = ThreatDetectionModel(
            gnn_input_dim=10,
            feature_dim=20,  # Will be updated
            num_classes=11
        ).to(self.device)
        
        self.model.load_state_dict(
            torch.load('models/saved_models/best_model.pth', map_location=self.device)
        )
        self.model.eval()
    
    def preprocess_event(self, event):
        """Preprocess incoming event for model prediction"""
        # Create feature vector
        features = []
        
        # Numerical features
        numerical_features = [
            'duration', 'src_bytes', 'dst_bytes', 'wrong_fragment',
            'urgent', 'hot', 'num_failed_logins', 'logged_in'
        ]
        
        for feat in numerical_features:
            features.append(event.get(feat, 0))
        
        # Protocol encoding
        protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS', 'FTP', 'SSH']
        protocol = event.get('protocol', 'TCP')
        features.extend([1 if p == protocol else 0 for p in protocols])
        
        # Add random graph features for simulation
        graph_features = np.random.randn(10)
        features.extend(graph_features)
        
        return np.array(features).reshape(1, -1)
    
    def predict_threat(self, features):
        """Predict threat type and score"""
        with torch.no_grad():
            features_tensor = torch.FloatTensor(features).to(self.device)
            
            # Simulate graph data
            graph_x = torch.randn(1, 10).to(self.device)
            edge_index = torch.randint(0, 1, (2, 2)).to(self.device)
            batch_idx = torch.LongTensor([0]).to(self.device)
            
            class_pred, threat_pred = self.model(
                type('GraphData', (), {'x': graph_x, 'edge_index': edge_index, 'batch': batch_idx})(),
                features_tensor
            )
            
            predicted_class = torch.argmax(class_pred, dim=1).item()
            threat_score = threat_pred.item()
            
            return predicted_class, threat_score
    
    def decide_action(self, threat_class, threat_score, event):
        """Use RL agent to decide defense action"""
        # Create state vector
        state = np.concatenate([
            [threat_score],
            [1 if threat_class != self.label_encoder.transform(['normal'])[0] else 0],
            [event.get('src_bytes', 0) / 1000000],
            [event.get('dst_bytes', 0) / 500000],
            np.random.randn(124)  # Simulated additional features
        ])
        
        # Get action from RL agent
        action_idx = self.rl_agent.select_action(state)
        action = self.rl_agent.actions[action_idx]
        
        return action, action_idx
    
    def process_event(self, event):
        """Process a single network event"""
        self.stats['total_events'] += 1
        
        # Preprocess
        features = self.preprocess_event(event)
        
        # Predict
        threat_class, threat_score = self.predict_threat(features)
        attack_type = self.label_encoder.inverse_transform([threat_class])[0]
        
        # Decide action
        action, action_idx = self.decide_action(threat_class, threat_score, event)
        
        # Update statistics
        is_actual_threat = event.get('is_attack', 0) == 1
        is_predicted_threat = attack_type != 'normal'
        
        if is_predicted_threat:
            self.stats['threats_detected'] += 1
        
        if is_predicted_threat and not is_actual_threat:
            self.stats['false_positives'] += 1
        
        # Record action
        self.stats['actions_taken'].append({
            'timestamp': datetime.now().isoformat(),
            'source_ip': event.get('source_ip'),
            'attack_type': attack_type,
            'threat_score': threat_score,
            'action': action,
            'confidence': max(0, 1 - threat_score)  # Simplified confidence
        })
        
        # Print result
        print(f"\n{'='*60}")
        print(f"Event from: {event.get('source_ip')}")
        print(f"Attack Type: {attack_type}")
        print(f"Threat Score: {threat_score:.4f}")
        print(f"Action Taken: {action}")
        print(f"Confidence: {max(0, 1 - threat_score):.2%}")
        
        # Print statistics
        if self.stats['total_events'] % 10 == 0:
            self.print_statistics()
    
    def print_statistics(self):
        """Print current statistics"""
        print(f"\n{'='*60}")
        print("SYSTEM STATISTICS:")
        print(f"Total Events Processed: {self.stats['total_events']}")
        print(f"Threats Detected: {self.stats['threats_detected']}")
        
        if self.stats['total_events'] > 0:
            detection_rate = self.stats['threats_detected'] / self.stats['total_events']
            print(f"Detection Rate: {detection_rate:.2%}")
        
        if self.stats['threats_detected'] > 0:
            fp_rate = self.stats['false_positives'] / max(1, self.stats['threats_detected'])
            print(f"False Positive Rate: {fp_rate:.2%}")
        
        # Recent actions
        print("\nRecent Actions:")
        for action in self.stats['actions_taken'][-5:]:
            print(f"  {action['timestamp']} - {action['source_ip']}: {action['action']}")
    
    def start_consuming(self):
        """Start consuming events from Kafka"""
        print("Starting Kafka Consumer for threat detection...")
        print("Waiting for events...\n")
        
        try:
            for message in self.consumer:
                event = message.value
                self.process_event(event)
                
        except KeyboardInterrupt:
            print("\nStopping consumer...")
            self.print_statistics()
        finally:
            self.consumer.close()

if __name__ == "__main__":
    consumer = ThreatDetectionConsumer()
    consumer.start_consuming()