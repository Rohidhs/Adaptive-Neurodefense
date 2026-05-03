# models/train_model.py
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import pickle
import json
from gnn_rl_model import ThreatDetectionModel, RLDefenseAgent
import warnings
warnings.filterwarnings('ignore')

class ThreatDetectionSystem:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.feature_columns = None
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        
    def prepare_data(self, df):
        """Prepare data for training"""
        print("Preparing data...")
        
        # Handle missing values
        df = df.fillna(df.mode().iloc[0])
        
        # Encode categorical features
        categorical_cols = ['protocol_type', 'service', 'flag']
        for col in categorical_cols:
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col].astype(str))
        
        # Features and labels
        feature_columns = [col for col in df.columns if col not in 
                          ['timestamp', 'attack_type', 'threat_score', 'is_attack']]
        self.feature_columns = feature_columns
        
        X = df[feature_columns].values
        y = self.label_encoder.fit_transform(df['attack_type'])
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Create simulated graph data (in real scenario, this would be actual graph data)
        # For simulation, we'll use a subset of features as node features
        def create_simulated_graph_features(X, num_nodes=10):
            graphs = []
            for i in range(0, len(X), num_nodes):
                batch_nodes = min(num_nodes, len(X) - i)
                node_features = X[i:i+batch_nodes]
                
                # Create random edges for simulation
                num_edges = batch_nodes * 2
                edge_index = np.random.randint(0, batch_nodes, size=(2, num_edges))
                
                graphs.append({
                    'node_features': node_features[:, :10],  # First 10 features as graph features
                    'edge_index': edge_index,
                    'batch': np.zeros(batch_nodes, dtype=int)
                })
            return graphs
        
        train_graphs = create_simulated_graph_features(X_train_scaled)
        test_graphs = create_simulated_graph_features(X_test_scaled)
        
        return (X_train_scaled, X_test_scaled, y_train, y_test, 
                train_graphs, test_graphs, feature_columns)
    
    def train_model(self, df, epochs=50, batch_size=64):
        """Train the threat detection model"""
        print("Starting model training...")
        
        # Prepare data
        (X_train, X_test, y_train, y_test, 
         train_graphs, test_graphs, feature_columns) = self.prepare_data(df)
        
        # Initialize model
        self.model = ThreatDetectionModel(
            gnn_input_dim=10,
            feature_dim=len(feature_columns),
            num_classes=len(self.label_encoder.classes_)
        ).to(self.device)
        
        # Optimizer and loss
        optimizer = optim.Adam(self.model.parameters(), lr=0.001, weight_decay=1e-5)
        scheduler = optim.lr_scheduler.ReduceLROnPlateau(optimizer, 'min', patience=5)
        
        class_weights = torch.FloatTensor(
            [1.0 / (np.sum(y_train == i) + 1) for i in range(len(self.label_encoder.classes_))]
        ).to(self.device)
        criterion_cls = nn.CrossEntropyLoss(weight=class_weights)
        criterion_reg = nn.MSELoss()
        
        # Convert to tensors
        X_train_tensor = torch.FloatTensor(X_train).to(self.device)
        y_train_tensor = torch.LongTensor(y_train).to(self.device)
        
        # Training loop
        best_accuracy = 0
        history = {'train_loss': [], 'val_accuracy': []}
        
        for epoch in range(epochs):
            self.model.train()
            
            # Mini-batch training
            permutation = torch.randperm(X_train_tensor.size()[0])
            epoch_loss = 0
            
            for i in range(0, X_train_tensor.size()[0], batch_size):
                indices = permutation[i:i+batch_size]
                batch_x = X_train_tensor[indices]
                batch_y = y_train_tensor[indices]
                
                # Simulate graph data for batch
                batch_graph_data = train_graphs[i % len(train_graphs)]
                graph_x = torch.FloatTensor(batch_graph_data['node_features']).to(self.device)
                edge_index = torch.LongTensor(batch_graph_data['edge_index']).to(self.device)
                batch_idx = torch.LongTensor(batch_graph_data['batch']).to(self.device)
                
                # Forward pass
                class_pred, threat_pred = self.model(
                    type('GraphData', (), {'x': graph_x, 'edge_index': edge_index, 'batch': batch_idx})(),
                    batch_x
                )
                
                # Loss calculation
                loss_cls = criterion_cls(class_pred, batch_y)
                
                # Simulated threat scores (in real scenario, use actual scores)
                threat_scores = torch.FloatTensor(
                    np.random.random(len(batch_y)) * (batch_y != 0).float().cpu().numpy()
                ).to(self.device)
                loss_reg = criterion_reg(threat_pred.squeeze(), threat_scores)
                
                loss = loss_cls + 0.1 * loss_reg
                
                # Backward pass
                optimizer.zero_grad()
                loss.backward()
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
                optimizer.step()
                
                epoch_loss += loss.item()
            
            avg_loss = epoch_loss / (X_train_tensor.size()[0] / batch_size)
            history['train_loss'].append(avg_loss)
            
            # Validation
            val_accuracy = self.evaluate(X_test, y_test, test_graphs)
            history['val_accuracy'].append(val_accuracy)
            
            scheduler.step(avg_loss)
            
            print(f"Epoch {epoch+1}/{epochs}, Loss: {avg_loss:.4f}, Val Accuracy: {val_accuracy:.4f}")
            
            # Save best model
            if val_accuracy > best_accuracy:
                best_accuracy = val_accuracy
                self.save_model('models/saved_models/best_model.pth')
        
        print(f"\nBest Validation Accuracy: {best_accuracy:.4f}")
        
        # Final evaluation
        self.evaluate(X_test, y_test, test_graphs, detailed=True)
        
        return history
    
    def evaluate(self, X_test, y_test, test_graphs, detailed=False):
        """Evaluate model performance"""
        if self.model is None:
            raise ValueError("Model not trained yet!")
        
        self.model.eval()
        with torch.no_grad():
            X_test_tensor = torch.FloatTensor(X_test).to(self.device)
            
            # Use first graph for testing (simplified)
            graph_data = test_graphs[0]
            graph_x = torch.FloatTensor(graph_data['node_features']).to(self.device)
            edge_index = torch.LongTensor(graph_data['edge_index']).to(self.device)
            batch_idx = torch.LongTensor(graph_data['batch']).to(self.device)
            
            # Predict in batches
            predictions = []
            threat_scores = []
            batch_size = 128
            
            for i in range(0, len(X_test_tensor), batch_size):
                batch_x = X_test_tensor[i:i+batch_size]
                
                class_pred, threat_pred = self.model(
                    type('GraphData', (), {'x': graph_x, 'edge_index': edge_index, 'batch': batch_idx})(),
                    batch_x
                )
                
                batch_preds = torch.argmax(class_pred, dim=1)
                predictions.extend(batch_preds.cpu().numpy())
                threat_scores.extend(threat_pred.squeeze().cpu().numpy())
        
        accuracy = accuracy_score(y_test[:len(predictions)], predictions)
        
        if detailed:
            print(f"\nTest Accuracy: {accuracy:.4f}")
            print("\nClassification Report:")
            print(classification_report(y_test[:len(predictions)], predictions, 
                                      target_names=self.label_encoder.classes_))
            
            print("\nConfusion Matrix:")
            cm = confusion_matrix(y_test[:len(predictions)], predictions)
            print(cm)
            
            # Calculate threat detection rate
            threat_detected = np.array(threat_scores) > 0.5
            actual_threats = (y_test[:len(predictions)] != self.label_encoder.transform(['normal'])[0])
            threat_accuracy = np.mean(threat_detected == actual_threats)
            print(f"\nThreat Detection Accuracy: {threat_accuracy:.4f}")
        
        return accuracy
    
    def save_model(self, path):
        """Save model and preprocessing objects"""
        torch.save(self.model.state_dict(), path)
        
        # Save preprocessing objects
        with open('models/saved_models/scaler.pkl', 'wb') as f:
            pickle.dump(self.scaler, f)
        
        with open('models/saved_models/label_encoder.pkl', 'wb') as f:
            pickle.dump(self.label_encoder, f)
        
        with open('models/saved_models/feature_columns.json', 'w') as f:
            json.dump(self.feature_columns, f)
        
        print(f"Model saved to {path}")
    
    def load_model(self, path):
        """Load trained model"""
        self.model = ThreatDetectionModel(
            gnn_input_dim=10,
            feature_dim=len(self.feature_columns) if self.feature_columns else 20,
            num_classes=len(self.label_encoder.classes_) if hasattr(self.label_encoder, 'classes_') else 11
        ).to(self.device)
        
        self.model.load_state_dict(torch.load(path, map_location=self.device))
        self.model.eval()
        print(f"Model loaded from {path}")

def main():
    # Load dataset
    print("Loading dataset...")
    df = pd.read_csv('data/cyber_threat_dataset.csv')
    
    # Initialize and train system
    system = ThreatDetectionSystem()
    history = system.train_model(df, epochs=30, batch_size=128)
    
    # Train RL agent
    print("\nTraining RL Defense Agent...")
    rl_agent = RLDefenseAgent()
    
    # Simulate RL training
    for episode in range(100):
        state = np.random.randn(128)
        action = rl_agent.select_action(state)
        reward = np.random.choice([-1, 0, 1])
        next_state = np.random.randn(128)
        done = episode == 99
        
        loss = rl_agent.train_step(state, action, reward, next_state, done)
        rl_agent.update_epsilon()
        
        if episode % 20 == 0:
            print(f"Episode {episode}, Loss: {loss:.4f}, Epsilon: {rl_agent.epsilon:.3f}")
    
    # Save RL agent
    torch.save(rl_agent.q_network.state_dict(), 'models/saved_models/rl_agent.pth')
    print("RL Agent saved")

if __name__ == "__main__":
    main()