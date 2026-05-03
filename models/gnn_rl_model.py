# models/gnn_rl_model.py
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GCNConv, global_mean_pool
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import warnings
warnings.filterwarnings('ignore')

class GraphNeuralNetwork(nn.Module):
    """GNN for network graph analysis"""
    def __init__(self, input_dim, hidden_dim=128, output_dim=64):
        super(GraphNeuralNetwork, self).__init__()
        self.conv1 = GCNConv(input_dim, hidden_dim)
        self.conv2 = GCNConv(hidden_dim, hidden_dim)
        self.conv3 = GCNConv(hidden_dim, output_dim)
        self.batch_norm1 = nn.BatchNorm1d(hidden_dim)
        self.batch_norm2 = nn.BatchNorm1d(hidden_dim)
        self.dropout = nn.Dropout(0.3)
        
    def forward(self, x, edge_index, batch=None):
        x = self.conv1(x, edge_index)
        x = F.relu(self.batch_norm1(x))
        x = self.dropout(x)
        
        x = self.conv2(x, edge_index)
        x = F.relu(self.batch_norm2(x))
        x = self.dropout(x)
        
        x = self.conv3(x, edge_index)
        
        if batch is not None:
            x = global_mean_pool(x, batch)
        
        return x

class ThreatDetectionModel(nn.Module):
    """Main threat detection model combining GNN and traditional features"""
    def __init__(self, gnn_input_dim=10, feature_dim=20, num_classes=11):
        super(ThreatDetectionModel, self).__init__()
        
        # GNN for graph-based features
        self.gnn = GraphNeuralNetwork(gnn_input_dim, hidden_dim=128, output_dim=64)
        
        # Feature extraction for traditional features
        self.feature_encoder = nn.Sequential(
            nn.Linear(feature_dim, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(128, 64),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Dropout(0.3)
        )
        
        # Combined classifier
        self.classifier = nn.Sequential(
            nn.Linear(64 + 64, 128),  # GNN output + feature encoder output
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(128, 64),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(64, num_classes)
        )
        
        # Threat score regressor
        self.threat_regressor = nn.Sequential(
            nn.Linear(64 + 64, 64),
            nn.ReLU(),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Linear(32, 1),
            nn.Sigmoid()
        )
        
    def forward(self, graph_data, features):
        # Process graph data
        graph_features = self.gnn(graph_data.x, graph_data.edge_index, graph_data.batch)
        
        # Process traditional features
        encoded_features = self.feature_encoder(features)
        
        # Combine features
        combined = torch.cat([graph_features, encoded_features], dim=1)
        
        # Get predictions
        classification = self.classifier(combined)
        threat_score = self.threat_regressor(combined)
        
        return classification, threat_score

class RLDefenseAgent:
    """Reinforcement Learning agent for automated defense actions"""
    def __init__(self, state_dim=128, action_dim=5):
        self.state_dim = state_dim
        self.action_dim = action_dim
        self.learning_rate = 0.001
        self.gamma = 0.99
        self.epsilon = 1.0
        self.epsilon_min = 0.01
        self.epsilon_decay = 0.995
        
        # Q-Network
        self.q_network = nn.Sequential(
            nn.Linear(state_dim, 256),
            nn.ReLU(),
            nn.Linear(256, 128),
            nn.ReLU(),
            nn.Linear(128, action_dim)
        )
        
        self.target_network = nn.Sequential(
            nn.Linear(state_dim, 256),
            nn.ReLU(),
            nn.Linear(256, 128),
            nn.ReLU(),
            nn.Linear(128, action_dim)
        )
        
        self.optimizer = torch.optim.Adam(self.q_network.parameters(), lr=self.learning_rate)
        self.loss_fn = nn.MSELoss()
        
        # Defense actions
        self.actions = [
            "no_action",
            "block_ip",
            "throttle_connection",
            "isolate_service",
            "trigger_alert"
        ]
    
    def select_action(self, state):
        if np.random.random() < self.epsilon:
            return np.random.randint(self.action_dim)
        else:
            with torch.no_grad():
                state_tensor = torch.FloatTensor(state).unsqueeze(0)
                q_values = self.q_network(state_tensor)
                return torch.argmax(q_values).item()
    
    def update_epsilon(self):
        self.epsilon = max(self.epsilon_min, self.epsilon * self.epsilon_decay)
    
    def train_step(self, state, action, reward, next_state, done):
        state = torch.FloatTensor(state)
        next_state = torch.FloatTensor(next_state)
        action = torch.LongTensor([action])
        reward = torch.FloatTensor([reward])
        
        # Current Q value
        current_q = self.q_network(state).gather(1, action.unsqueeze(1))
        
        # Next Q value from target network
        with torch.no_grad():
            next_q = self.target_network(next_state).max(1)[0].unsqueeze(1)
            target_q = reward + (1 - done) * self.gamma * next_q
        
        # Compute loss
        loss = self.loss_fn(current_q, target_q)
        
        # Optimize
        self.optimizer.zero_grad()
        loss.backward()
        self.optimizer.step()
        
        return loss.item()