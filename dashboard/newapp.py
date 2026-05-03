# finalapp.py
import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime
import random
import time

# Page configuration
st.set_page_config(
    page_title="Adaptive NeuroDefense Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1E88E5;
        text-align: center;
        margin-bottom: 1rem;
    }
    .sub-header {
        font-size: 1.2rem;
        color: #546E7A;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 20px;
        border-radius: 10px;
        color: white;
        text-align: center;
    }
    .threat-high { color: #FF5252; }
    .threat-medium { color: #FF9800; }
    .threat-low { color: #4CAF50; }
    .stProgress > div > div > div > div {
        background: linear-gradient(90deg, #4CAF50, #8BC34A, #FFC107, #FF9800, #FF5252);
    }
    .prediction-result {
        animation: fadeIn 0.5s ease-in;
    }
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(20px); }
        to { opacity: 1; transform: translateY(0); }
    }
    .stButton > button {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
        transition: all 0.3s ease;
    }
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(0,0,0,0.2);
    }
    .autonomous-mode {
        border-left: 4px solid #4CAF50;
        background-color: #4CAF5010;
        padding: 10px;
        border-radius: 5px;
    }
    .semi-autonomous-mode {
        border-left: 4px solid #FF9800;
        background-color: #FF980010;
        padding: 10px;
        border-radius: 5px;
    }
    .manual-mode {
        border-left: 4px solid #FF5252;
        background-color: #FF525210;
        padding: 10px;
        border-radius: 5px;
    }
</style>
""", unsafe_allow_html=True)

class ThreatSimulator:
    """Simulate real-time threat data"""
    
    def __init__(self):
        self.attack_types = ['normal', 'dos', 'probe', 'r2l', 'u2r', 'malware', 'phishing', 'ransomware', 'zero-day']
        self.ip_pool = [f'192.168.{i}.{j}' for i in range(1, 10) for j in range(1, 50)]
        self.protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS']
        self.services = ['http', 'smtp', 'ftp', 'ssh', 'dns', 'pop3']
        
    def generate_event(self, response_mode="Autonomous", threat_threshold=0.6):
        """Generate a simulated network event with response mode logic"""
        is_attack = random.random() < 0.3
        
        if is_attack:
            attack_type = random.choice(self.attack_types[1:])
            threat_score = random.uniform(0.4, 0.99)
            severity = 'HIGH' if threat_score > 0.8 else 'MEDIUM' if threat_score > 0.6 else 'LOW'
        else:
            attack_type = 'normal'
            threat_score = random.uniform(0.0, 0.3)
            severity = 'LOW'
        
        # Determine action based on response mode and threat score
        action, action_color, requires_approval = self._determine_action(
            threat_score, response_mode, threat_threshold, attack_type
        )
        
        event = {
            'timestamp': datetime.now(),
            'source_ip': random.choice(self.ip_pool),
            'dest_ip': f'10.0.{random.randint(0,255)}.{random.randint(1,254)}',
            'source_port': random.randint(1024, 65535),
            'dest_port': random.choice([80, 443, 22, 25, 53]),
            'protocol': random.choice(self.protocols),
            'service': random.choice(self.services),
            'src_bytes': random.randint(100, 1000000),
            'dst_bytes': random.randint(100, 500000),
            'duration': random.uniform(0.1, 60),
            'num_failed_logins': random.randint(0, 10),
            'logged_in': random.choice([0, 1]),
            'attack_type': attack_type,
            'threat_score': threat_score,
            'severity': severity,
            'action': action,
            'action_color': action_color,
            'requires_approval': requires_approval,
            'confidence': 1 - threat_score,
            'is_attack': 1 if is_attack else 0,
            'response_mode': response_mode,
            'approved': not requires_approval  # Auto-approved if no approval needed
        }
        
        return event
    
    def _determine_action(self, threat_score, response_mode, threat_threshold, attack_type):
        """Determine action based on response mode"""
        
        # If threat is below threshold, always allow
        if threat_score < threat_threshold:
            return '✅ ALLOW', '#4CAF50', False
        
        # Determine base action based on threat score
        if threat_score > 0.8:
            base_action = '🚫 BLOCK IP'
            base_color = '#FF5252'
        elif threat_score > 0.6:
            base_action = '⚠️ THROTTLE'
            base_color = '#FF9800'
        elif threat_score > 0.4:
            base_action = '🔍 INVESTIGATE'
            base_color = '#FFC107'
        else:
            base_action = '✅ ALLOW'
            base_color = '#4CAF50'
        
        # Apply response mode logic
        if response_mode == "Autonomous":
            # Fully automatic - take action immediately
            return base_action, base_color, False
            
        elif response_mode == "Semi-Autonomous":
            # Requires approval for high severity threats only
            requires_approval = threat_score > 0.7
            if requires_approval:
                action = f"⏳ PENDING: {base_action}"
                color = '#FF9800'
            else:
                action = base_action
                color = base_color
            return action, color, requires_approval
            
        elif response_mode == "Manual":
            # All threats require manual approval
            action = f"⏳ REVIEW: {base_action}"
            color = '#FF5252'
            return action, color, True
            
        return base_action, base_color, False

class AdaptiveNeuroDefenseDashboard:
    """Main dashboard class"""
    
    def __init__(self):
        self.simulator = ThreatSimulator()
        
    def initialize_session_state(self):
        """Initialize all session state variables"""
        if 'events_data' not in st.session_state:
            st.session_state.events_data = []
            
        if 'pending_actions' not in st.session_state:
            st.session_state.pending_actions = []
            
        if 'approved_actions' not in st.session_state:
            st.session_state.approved_actions = []
            
        if 'system_metrics' not in st.session_state:
            st.session_state.system_metrics = {
                'total_events': 0,
                'threats_detected': 0,
                'false_positives': 0,
                'true_positives': 0,
                'model_confidence': 95.7,
                'cpu_usage': 45.3,
                'memory_usage': 62.1,
                'network_traffic': 1245,
                'response_time': 12.3,
                'auto_responses': 0,
                'manual_approvals': 0,
                'pending_reviews': 0
            }
            
        if 'attack_distribution' not in st.session_state:
            st.session_state.attack_distribution = {attack: 0 for attack in self.simulator.attack_types}
            
        if 'last_update' not in st.session_state:
            st.session_state.last_update = datetime.now()
            
        if 'auto_refresh' not in st.session_state:
            st.session_state.auto_refresh = True
            
        if 'simulation_speed' not in st.session_state:
            st.session_state.simulation_speed = 5
            
        if 'show_alerts' not in st.session_state:
            st.session_state.show_alerts = True
            
        if 'threat_threshold' not in st.session_state:
            st.session_state.threat_threshold = 0.6
            
        if 'action_mode' not in st.session_state:
            st.session_state.action_mode = "Autonomous"
            
        # Prediction result state
        if 'prediction_result' not in st.session_state:
            st.session_state.prediction_result = None
            
        if 'batch_result' not in st.session_state:
            st.session_state.batch_result = None
            
        if 'prediction_timestamp' not in st.session_state:
            st.session_state.prediction_timestamp = None
    
    def update_data(self):
        """Update dashboard data with new simulated events"""
        event = self.simulator.generate_event(
            response_mode=st.session_state.action_mode,
            threat_threshold=st.session_state.threat_threshold
        )
        
        # Handle pending approvals for Semi-Autonomous and Manual modes
        if event['requires_approval']:
            st.session_state.pending_actions.append({
                'event': event,
                'timestamp': event['timestamp'],
                'status': 'pending'
            })
            st.session_state.system_metrics['pending_reviews'] += 1
        else:
            # Auto-approved action
            st.session_state.events_data.append(event)
            st.session_state.system_metrics['auto_responses'] += 1
        
        # Keep pending actions list manageable
        if len(st.session_state.pending_actions) > 50:
            st.session_state.pending_actions = st.session_state.pending_actions[-50:]
        
        # Add to events list (but only approved events)
        max_events = 1000
        if len(st.session_state.events_data) > max_events:
            st.session_state.events_data = st.session_state.events_data[-max_events:]
        
        # Update system metrics
        st.session_state.system_metrics['total_events'] += 1
        
        if event['is_attack'] == 1:
            st.session_state.system_metrics['threats_detected'] += 1
            if event['threat_score'] > 0.5:
                st.session_state.system_metrics['true_positives'] += 1
            else:
                st.session_state.system_metrics['false_positives'] += 1
        
        # Update attack distribution
        st.session_state.attack_distribution[event['attack_type']] += 1
        
        # Update system metrics with randomness
        st.session_state.system_metrics['model_confidence'] = max(85, min(99, 
            st.session_state.system_metrics['model_confidence'] + random.uniform(-0.5, 0.5)))
        
        st.session_state.system_metrics['cpu_usage'] = max(30, min(80,
            st.session_state.system_metrics['cpu_usage'] + random.uniform(-2, 2)))
        
        st.session_state.system_metrics['memory_usage'] = max(50, min(75,
            st.session_state.system_metrics['memory_usage'] + random.uniform(-1, 1)))
        
        st.session_state.system_metrics['network_traffic'] = max(800, min(2000,
            st.session_state.system_metrics['network_traffic'] + random.uniform(-50, 50)))
        
        st.session_state.system_metrics['response_time'] = max(5, min(100,
            st.session_state.system_metrics['response_time'] + random.uniform(-1, 1)))
        
        return event
    
    def approve_action(self, action_index):
        """Approve a pending action"""
        if action_index < len(st.session_state.pending_actions):
            pending = st.session_state.pending_actions[action_index]
            event = pending['event']
            
            # Clean up the action text
            clean_action = event['action'].replace('⏳ PENDING: ', '').replace('⏳ REVIEW: ', '')
            event['action'] = clean_action
            event['approved'] = True
            
            # Add to events data
            st.session_state.events_data.append(event)
            
            # Update metrics
            st.session_state.system_metrics['manual_approvals'] += 1
            st.session_state.system_metrics['pending_reviews'] -= 1
            
            # Remove from pending
            st.session_state.pending_actions.pop(action_index)
            
            # Show notification
            if st.session_state.show_alerts:
                st.toast(f"✅ Action approved: {clean_action}", icon="✅")
            
            return True
        return False
    
    def reject_action(self, action_index):
        """Reject a pending action"""
        if action_index < len(st.session_state.pending_actions):
            pending = st.session_state.pending_actions[action_index]
            event = pending['event']
            
            # Log rejection
            event['action'] = f"❌ REJECTED: {event['action']}"
            event['approved'] = False
            
            # Update metrics
            st.session_state.system_metrics['pending_reviews'] -= 1
            
            # Remove from pending
            st.session_state.pending_actions.pop(action_index)
            
            # Show notification
            if st.session_state.show_alerts:
                st.toast(f"❌ Action rejected: No action taken", icon="❌")
            
            return True
        return False
    
    def render_header(self):
        """Render dashboard header"""
        col1, col2, col3 = st.columns([2, 3, 1])
        
        with col1:
            st.markdown("🛡️", unsafe_allow_html=True)
        
        with col2:
            st.markdown("<h1 class='main-header'>🛡️ Adaptive NeuroDefense</h1>", unsafe_allow_html=True)
            st.markdown("<p class='sub-header'>AI-Powered Self-Healing Cybersecurity System</p>", unsafe_allow_html=True)
        
        with col3:
            current_time = datetime.now().strftime("%H:%M:%S")
            st.metric("🕒 System Time", current_time)
            st.markdown(f"<div style='color: #4CAF50; font-weight: bold;'>● LIVE</div>", unsafe_allow_html=True)
    
    def render_metrics(self):
        """Render system metrics"""
        col1, col2, col3, col4, col5 = st.columns(5)
        
        with col1:
            delta = random.randint(1, 10) if st.session_state.system_metrics['total_events'] > 0 else 0
            st.metric(
                "📊 Total Events", 
                f"{st.session_state.system_metrics['total_events']:,}",
                delta=f"+{delta}"
            )
        
        with col2:
            threat_rate = (st.session_state.system_metrics['threats_detected'] / max(1, st.session_state.system_metrics['total_events'])) * 100
            st.metric(
                "⚠️ Threat Rate", 
                f"{threat_rate:.1f}%",
                delta_color="inverse"
            )
        
        with col3:
            st.metric(
                "🎯 Model Confidence", 
                f"{st.session_state.system_metrics['model_confidence']:.1f}%",
                delta=f"{random.uniform(-0.5, 0.5):.1f}%"
            )
        
        with col4:
            detection_rate = (st.session_state.system_metrics['true_positives'] / max(1, st.session_state.system_metrics['threats_detected'])) * 100
            st.metric(
                "✅ Detection Accuracy", 
                f"{detection_rate:.1f}%",
                delta=f"{random.uniform(0, 1):.1f}%"
            )
        
        with col5:
            st.metric(
                "⚡ Response Time", 
                f"{st.session_state.system_metrics['response_time']:.1f}ms",
                delta=f"{random.uniform(-1, 1):.1f}ms"
            )
    
    def render_response_mode_indicator(self):
        """Render current response mode indicator"""
        mode = st.session_state.action_mode
        mode_config = {
            "Autonomous": {"color": "#4CAF50", "icon": "🤖", "desc": "Fully automatic threat response"},
            "Semi-Autonomous": {"color": "#FF9800", "icon": "⚡", "desc": "Auto-response for low threats, approval needed for high threats"},
            "Manual": {"color": "#FF5252", "icon": "👨‍💻", "desc": "All threats require manual approval"}
        }
        
        config = mode_config.get(mode, mode_config["Autonomous"])
        
        st.markdown(f"""
        <div class='{mode.lower().replace('-', '')}-mode' style='margin: 10px 0; padding: 15px; border-radius: 10px; background-color: {config['color']}10;'>
            <div style='display: flex; justify-content: space-between; align-items: center;'>
                <div>
                    <span style='font-size: 1.5rem;'>{config['icon']}</span>
                    <span style='font-weight: bold; margin-left: 10px;'>Response Mode: {mode}</span>
                    <span style='margin-left: 15px; font-size: 0.9rem; color: {config['color']};'>{config['desc']}</span>
                </div>
                <div>
                    <span style='font-size: 0.9rem;'>🤖 Auto: {st.session_state.system_metrics['auto_responses']} | 
                    👨‍💻 Manual: {st.session_state.system_metrics['manual_approvals']} | 
                    ⏳ Pending: {st.session_state.system_metrics['pending_reviews']}</span>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    def render_system_health(self):
        """Render system health indicators"""
        st.subheader("📈 System Health Monitor")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            cpu_value = st.session_state.system_metrics['cpu_usage']
            st.progress(cpu_value / 100, text=f"CPU Usage: {cpu_value:.1f}%")
        
        with col2:
            mem_value = st.session_state.system_metrics['memory_usage']
            st.progress(mem_value / 100, text=f"Memory Usage: {mem_value:.1f}%")
        
        with col3:
            st.progress(
                st.session_state.system_metrics['model_confidence'] / 100,
                text=f"Model Confidence: {st.session_state.system_metrics['model_confidence']:.1f}%"
            )
        
        with col4:
            traffic_value = st.session_state.system_metrics['network_traffic']
            normalized_traffic = min(100, (traffic_value / 2000) * 100)
            st.progress(normalized_traffic / 100, text=f"Network Traffic: {traffic_value:,} Mbps")
    
    def render_threat_timeline(self):
        """Render threat timeline chart"""
        st.subheader("📊 Real-time Threat Timeline")
        
        if len(st.session_state.events_data) > 0:
            recent_events = st.session_state.events_data[-50:]
            timestamps = [e['timestamp'] for e in recent_events]
            threat_scores = [e['threat_score'] * 100 for e in recent_events]
            attack_types = [e['attack_type'] for e in recent_events]
            
            color_map = {
                'normal': '#4CAF50',
                'dos': '#FF5252',
                'probe': '#FF9800',
                'r2l': '#FFC107',
                'u2r': '#9C27B0',
                'malware': '#F44336',
                'phishing': '#2196F3',
                'ransomware': '#795548',
                'zero-day': '#000000'
            }
            
            colors = [color_map.get(at, '#757575') for at in attack_types]
            
            fig = go.Figure()
            
            fig.add_trace(go.Scatter(
                x=timestamps,
                y=threat_scores,
                mode='lines+markers',
                name='Threat Score',
                line=dict(color='#1E88E5', width=2),
                marker=dict(
                    size=8,
                    color=colors,
                    symbol='circle'
                ),
                hovertemplate='<b>Time:</b> %{x}<br>' +
                            '<b>Threat Score:</b> %{y:.1f}%<br>' +
                            '<b>Attack Type:</b> %{text}<extra></extra>',
                text=attack_types
            ))
            
            fig.add_hline(y=40, line_dash="dash", line_color="green", annotation_text="Low Risk")
            fig.add_hline(y=60, line_dash="dash", line_color="orange", annotation_text="Medium Risk")
            fig.add_hline(y=80, line_dash="dash", line_color="red", annotation_text="High Risk")
            
            fig.update_layout(
                height=400,
                xaxis_title="Time",
                yaxis_title="Threat Score (%)",
                hovermode="x unified",
                template="plotly_dark",
                plot_bgcolor='rgba(0,0,0,0)',
                paper_bgcolor='rgba(0,0,0,0)',
                font_color='white'
            )
            
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("📊 Generating threat data... This will appear shortly.")
            st.progress(0.5, text="Initializing threat monitoring...")
    
    def render_attack_distribution(self):
        """Render attack distribution pie chart"""
        st.subheader("🎯 Attack Type Distribution")
        
        attack_data = pd.DataFrame.from_dict(st.session_state.attack_distribution, orient='index', columns=['count'])
        attack_data = attack_data[attack_data['count'] > 0]
        
        if len(attack_data) > 0:
            fig = go.Figure(data=[go.Pie(
                labels=attack_data.index,
                values=attack_data['count'],
                hole=0.4,
                marker_colors=px.colors.qualitative.Set3,
                textinfo='label+percent',
                hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>'
            )])
            
            fig.update_layout(
                height=400,
                template="plotly_dark",
                plot_bgcolor='rgba(0,0,0,0)',
                paper_bgcolor='rgba(0,0,0,0)',
                font_color='white'
            )
            
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("📊 Waiting for attack data...")
    
    def render_recent_events(self):
        """Render recent threat events table"""
        st.subheader("📋 Recent Threat Events")
        
        if len(st.session_state.events_data) > 0:
            recent_events = st.session_state.events_data[-10:][::-1]
            
            event_df = pd.DataFrame(recent_events)
            
            display_df = event_df[[
                'timestamp', 'source_ip', 'dest_ip', 'attack_type', 
                'threat_score', 'severity', 'action', 'response_mode'
            ]].copy()
            
            display_df['timestamp'] = display_df['timestamp'].dt.strftime('%H:%M:%S')
            display_df['threat_score'] = display_df['threat_score'].apply(lambda x: f"{x*100:.1f}%")
            
            def color_severity(val):
                if val == 'HIGH':
                    return 'color: #FF5252; font-weight: bold'
                elif val == 'MEDIUM':
                    return 'color: #FF9800'
                else:
                    return 'color: #4CAF50'
            
            st.dataframe(
                display_df.style.applymap(color_severity, subset=['severity']),
                use_container_width=True,
                height=400
            )
        else:
            st.info("📋 No events yet. System initializing...")
    
    def render_pending_approvals(self):
        """Render pending approval actions panel"""
        if st.session_state.pending_actions:
            st.subheader("⏳ Pending Approvals")
            st.markdown(f"**{len(st.session_state.pending_actions)}** actions waiting for review")
            
            for idx, pending in enumerate(st.session_state.pending_actions):
                event = pending['event']
                
                with st.container():
                    col1, col2, col3 = st.columns([3, 1, 1])
                    
                    with col1:
                        st.markdown(f"""
                        **{event['timestamp'].strftime('%H:%M:%S')}** - {event['attack_type'].upper()}
                        - From: {event['source_ip']}
                        - Threat Score: {event['threat_score']*100:.1f}%
                        - Action: {event['action']}
                        """)
                    
                    with col2:
                        if st.button(f"✅ Approve", key=f"approve_{idx}"):
                            self.approve_action(idx)
                            st.rerun()
                    
                    with col3:
                        if st.button(f"❌ Reject", key=f"reject_{idx}"):
                            self.reject_action(idx)
                            st.rerun()
                    
                    st.divider()
        else:
            if st.session_state.action_mode != "Autonomous":
                st.info("✅ No pending approvals. All threats have been handled.")
    
    def render_defense_actions(self):
        """Render defense actions panel"""
        st.subheader("🛡️ Active Defense Actions")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            blocked_ips = len([e for e in st.session_state.events_data if 'BLOCK' in e['action']])
            st.metric(
                "🚫 IP Blocks", 
                f"{blocked_ips}",
                delta=f"+{len([e for e in st.session_state.events_data[-10:] if 'BLOCK' in e['action']])}"
            )
        
        with col2:
            throttled = len([e for e in st.session_state.events_data if 'THROTTLE' in e['action']])
            st.metric(
                "⚠️ Throttled", 
                f"{throttled}",
                delta=f"+{len([e for e in st.session_state.events_data[-10:] if 'THROTTLE' in e['action']])}"
            )
        
        with col3:
            investigated = len([e for e in st.session_state.events_data if 'INVESTIGATE' in e['action']])
            st.metric(
                "🔍 Investigated", 
                f"{investigated}",
                delta=f"+{len([e for e in st.session_state.events_data[-10:] if 'INVESTIGATE' in e['action']])}"
            )
        
        with col4:
            auto_responses = st.session_state.system_metrics['auto_responses']
            st.metric(
                "🤖 Auto Responses", 
                f"{auto_responses}",
                help="Threats automatically handled by AI"
            )
        
        # Show pending approvals if in Semi-Autonomous or Manual mode
        if st.session_state.action_mode in ["Semi-Autonomous", "Manual"]:
            self.render_pending_approvals()
        
        st.subheader("📝 Defense Action Log")
        
        defense_events = [e for e in st.session_state.events_data[-10:] if e['action'] != '✅ ALLOW']
        
        if defense_events:
            for event in defense_events:
                with st.expander(f"{event['timestamp'].strftime('%H:%M:%S')} - {event['action']}"):
                    st.write(f"**Target IP:** {event['source_ip']}")
                    st.write(f"**Attack Type:** {event['attack_type'].upper()}")
                    st.write(f"**Threat Score:** {event['threat_score']*100:.1f}%")
                    st.write(f"**Response Mode:** {event['response_mode']}")
                    st.write(f"**Confidence:** {event['confidence']*100:.1f}%")
                    st.progress(event['threat_score'], text="Threat Level")
        else:
            st.info("No defense actions recorded yet. System monitoring for threats...")
    
    def render_prediction_interface(self):
        """Render threat prediction interface - FIXED to prevent auto-refresh"""
        st.subheader("🔮 Threat Prediction Interface")
        
        tab1, tab2 = st.tabs(["Single Prediction", "Batch Analysis"])
        
        with tab1:
            col1, col2 = st.columns(2)
            
            with col1:
                source_ip = st.text_input("Source IP", "192.168.1.100", key="pred_source_ip")
                dest_ip = st.text_input("Destination IP", "10.0.0.1", key="pred_dest_ip")
                protocol = st.selectbox("Protocol", ["TCP", "UDP", "ICMP", "HTTP", "HTTPS"], key="pred_protocol")
                service = st.selectbox("Service", ["http", "smtp", "ftp", "ssh", "dns"], key="pred_service")
            
            with col2:
                src_bytes = st.number_input("Source Bytes", min_value=0, max_value=10000000, value=1500, key="pred_src_bytes")
                dst_bytes = st.number_input("Destination Bytes", min_value=0, max_value=10000000, value=2500, key="pred_dst_bytes")
                num_failed_logins = st.number_input("Failed Logins", min_value=0, max_value=100, value=0, key="pred_failed_logins")
                duration = st.number_input("Duration (seconds)", min_value=0.0, max_value=3600.0, value=1.5, key="pred_duration")
            
            # Use a unique key for the button to prevent state conflicts
            analyze_button = st.button("🔍 Analyze Threat", type="primary", use_container_width=True, key="analyze_threat_button")
            
            if analyze_button:
                with st.spinner("🧠 AI Analyzing network patterns..."):
                    time.sleep(1.5)
                    
                    # Generate prediction
                    threat_score = random.uniform(0.1, 0.95)
                    
                    if threat_score > 0.8:
                        attack_type = random.choice(['dos', 'ransomware', 'zero-day'])
                        severity = "HIGH"
                        action = "🚫 BLOCK IMMEDIATELY"
                        color = "#FF5252"
                        confidence = random.uniform(85, 98)
                    elif threat_score > 0.6:
                        attack_type = random.choice(['probe', 'malware', 'phishing'])
                        severity = "MEDIUM"
                        action = "⚠️ THROTTLE & MONITOR"
                        color = "#FF9800"
                        confidence = random.uniform(75, 90)
                    elif threat_score > 0.4:
                        attack_type = "suspicious"
                        severity = "LOW"
                        action = "🔍 INVESTIGATE"
                        color = "#FFC107"
                        confidence = random.uniform(60, 80)
                    else:
                        attack_type = "normal"
                        severity = "NONE"
                        action = "✅ ALLOW"
                        color = "#4CAF50"
                        confidence = random.uniform(85, 99)
                    
                    # Store result in session state
                    st.session_state.prediction_result = {
                        'threat_score': threat_score,
                        'attack_type': attack_type,
                        'severity': severity,
                        'action': action,
                        'color': color,
                        'confidence': confidence,
                        'source_ip': source_ip,
                        'dest_ip': dest_ip,
                        'timestamp': datetime.now()
                    }
                    st.session_state.prediction_timestamp = datetime.now()
                    st.rerun()
            
            # Display prediction result if exists (persistent)
            if st.session_state.prediction_result is not None:
                result = st.session_state.prediction_result
                
                # Add a clear button
                if st.button("🗑️ Clear Results", key="clear_prediction"):
                    st.session_state.prediction_result = None
                    st.rerun()
                
                st.markdown("---")
                st.markdown("### 📊 Prediction Results")
                
                result_col1, result_col2, result_col3 = st.columns(3)
                
                with result_col1:
                    st.metric("Threat Score", f"{result['threat_score']*100:.1f}%", 
                             delta="High Risk" if result['threat_score'] > 0.7 else "Low Risk")
                
                with result_col2:
                    st.metric("Attack Type", result['attack_type'].upper())
                
                with result_col3:
                    st.metric("Severity", result['severity'])
                
                st.markdown(f"""
                <div class='prediction-result' style='background-color: {result['color']}20; padding: 20px; border-radius: 10px; border-left: 5px solid {result['color']}; margin-top: 10px;'>
                    <h4 style='color: {result['color']}; margin: 0;'>🎯 Recommended Action: {result['action']}</h4>
                    <p style='margin: 10px 0 0 0;'>Confidence: {result['confidence']:.1f}%</p>
                    <p style='margin: 5px 0 0 0;'>Source: {result['source_ip']} → {result['dest_ip']}</p>
                    <p style='margin: 5px 0 0 0; font-size: 0.8rem;'>Analyzed at: {result['timestamp'].strftime('%H:%M:%S')}</p>
                </div>
                """, unsafe_allow_html=True)
        
        with tab2:
            st.write("📁 Upload a CSV file with network traffic data for batch analysis")
            
            uploaded_file = st.file_uploader("Choose CSV file", type="csv", key="batch_file_uploader")
            
            if uploaded_file is not None:
                try:
                    df = pd.read_csv(uploaded_file)
                    st.success(f"✅ File uploaded: {uploaded_file.name}")
                    st.info(f"📊 Records found: {len(df):,}")
                    
                    # Use a unique key for batch button
                    run_batch_button = st.button("🚀 Run Batch Analysis", type="primary", key="run_batch_button")
                    
                    if run_batch_button:
                        progress_bar = st.progress(0)
                        status_text = st.empty()
                        
                        for i in range(100):
                            progress_bar.progress(i + 1)
                            status_text.text(f"🧠 Analyzing... {i+1}%")
                            time.sleep(0.02)
                        
                        threats_found = random.randint(1, max(1, len(df) // 10))
                        accuracy = random.uniform(85, 99)
                        
                        # Store batch result
                        st.session_state.batch_result = {
                            'total_records': len(df),
                            'threats_found': threats_found,
                            'accuracy': accuracy,
                            'timestamp': datetime.now()
                        }
                        st.rerun()
                    
                    # Display batch result if exists
                    if st.session_state.batch_result is not None:
                        result = st.session_state.batch_result
                        
                        col1, col2, col3 = st.columns(3)
                        
                        with col1:
                            st.metric("Total Records", f"{result['total_records']:,}")
                        
                        with col2:
                            st.metric("Threats Detected", f"{result['threats_found']}")
                        
                        with col3:
                            st.metric("Detection Accuracy", f"{result['accuracy']:.1f}%")
                        
                        st.balloons()
                        st.success(f"✅ Analysis complete! {result['threats_found']} potential threats identified.")
                        
                        # Add clear batch results button
                        if st.button("🗑️ Clear Batch Results", key="clear_batch"):
                            st.session_state.batch_result = None
                            st.rerun()
                        
                except Exception as e:
                    st.error(f"❌ Error processing file: {str(e)}")
    
    def render_insights_panel(self):
        """Render AI insights panel"""
        st.subheader("🤖 AI Insights & Recommendations")
        
        insights = []
        
        # Response mode insight
        mode_insight = {
            "Autonomous": "System is in fully autonomous mode. All threats are being handled automatically.",
            "Semi-Autonomous": "System is in semi-autonomous mode. High-severity threats require your approval.",
            "Manual": "System is in manual mode. All threat responses require your approval."
        }
        
        insights.append({
            "title": f"🎮 Current Response Mode: {st.session_state.action_mode}",
            "content": mode_insight.get(st.session_state.action_mode, "System operational"),
            "severity": "low",
            "recommendation": self._get_mode_recommendation()
        })
        
        # Generate dynamic insights based on actual data
        if len(st.session_state.events_data) > 10:
            recent_threats = [e for e in st.session_state.events_data[-50:] if e['is_attack'] == 1]
            if recent_threats:
                most_common = max(set([e['attack_type'] for e in recent_threats]), 
                                key=[e['attack_type'] for e in recent_threats].count)
                insights.append({
                    "title": "📈 Threat Trend Analysis",
                    "content": f"Detected {len(recent_threats)} threats in the last 50 events. " +
                              f"Most common attack: {most_common.upper()}",
                    "severity": "high" if len(recent_threats) > 20 else "medium",
                    "recommendation": f"Increase monitoring for {most_common} attacks and enable rate limiting"
                })
        
        # Model performance insight
        if st.session_state.system_metrics['model_confidence'] > 90:
            insights.append({
                "title": "🔄 Model Performance",
                "content": f"Current model confidence is {st.session_state.system_metrics['model_confidence']:.1f}%. " +
                          "AI model performing optimally with high accuracy.",
                "severity": "low",
                "recommendation": "Schedule regular retraining every 24 hours to maintain performance"
            })
        else:
            insights.append({
                "title": "⚠️ Model Performance Alert",
                "content": f"Model confidence has dropped to {st.session_state.system_metrics['model_confidence']:.1f}%. " +
                          "Possible model drift detected.",
                "severity": "high",
                "recommendation": "Immediate model retraining recommended with latest threat data"
            })
        
        # System health insight
        if st.session_state.system_metrics['cpu_usage'] < 70:
            insights.append({
                "title": "⚡ System Optimization",
                "content": f"System running efficiently with CPU at {st.session_state.system_metrics['cpu_usage']:.1f}%. " +
                          "Network traffic within normal parameters.",
                "severity": "low",
                "recommendation": "System health optimal. Continue monitoring."
            })
        else:
            insights.append({
                "title": "🚨 System Stress Detected",
                "content": f"High CPU usage ({st.session_state.system_metrics['cpu_usage']:.1f}%) detected. " +
                          "System under heavy load.",
                "severity": "medium",
                "recommendation": "Consider scaling resources or optimizing processing pipeline"
            })
        
        # Anomaly detection insight
        if len(st.session_state.events_data) > 10:
            failed_logins = [e for e in st.session_state.events_data[-100:] if e['num_failed_logins'] > 3]
            if failed_logins:
                insights.append({
                    "title": "🔍 Anomaly Detection Alert",
                    "content": f"Detected {len(failed_logins)} events with multiple failed login attempts in recent traffic. " +
                              "Potential brute force or credential stuffing attack.",
                    "severity": "high" if len(failed_logins) > 20 else "medium",
                    "recommendation": "Enable account lockout policies, implement CAPTCHA, and consider geo-fencing"
                })
        
        # Attack pattern insight
        attack_count = sum(1 for e in st.session_state.events_data[-100:] if e['is_attack'] == 1)
        if attack_count > 30:
            insights.append({
                "title": "📊 Attack Pattern Analysis",
                "content": f"Attack rate at {attack_count}% in last 100 events. " +
                          "Abnormal pattern detected.",
                "severity": "high",
                "recommendation": "Increase security posture, enable aggressive rate limiting"
            })
        
        # Approval insights for Semi-Autonomous mode
        if st.session_state.action_mode == "Semi-Autonomous" and st.session_state.system_metrics['pending_reviews'] > 5:
            insights.append({
                "title": "⏳ Approval Backlog",
                "content": f"There are {st.session_state.system_metrics['pending_reviews']} pending approvals. " +
                          "Consider reviewing them or switching to Autonomous mode.",
                "severity": "medium",
                "recommendation": "Review pending approvals or temporarily enable Autonomous mode"
            })
        
        if not insights:
            insights.append({
                "title": "🤖 AI System Ready",
                "content": "System is monitoring for threats. Insights will appear as data is collected.",
                "severity": "low",
                "recommendation": "Allow system to collect more data for better insights"
            })
        
        for insight in insights:
            severity_color = {
                "high": "#FF5252",
                "medium": "#FF9800",
                "low": "#4CAF50"
            }.get(insight["severity"], "#757575")
            
            with st.expander(f"{insight['title']}", expanded=False):
                st.write(insight["content"])
                st.markdown(f"**💡 Recommendation:** {insight['recommendation']}")
                severity_value = {"high": 90, "medium": 60, "low": 30}.get(insight["severity"], 50)
                st.progress(severity_value / 100, text=f"⚠️ Severity Level: {insight['severity'].upper()}")
    
    def _get_mode_recommendation(self):
        """Get mode-specific recommendation"""
        mode = st.session_state.action_mode
        pending = st.session_state.system_metrics['pending_reviews']
        
        if mode == "Autonomous":
            if pending > 0:
                return "System is handling everything automatically. No action needed."
            else:
                return "Autonomous mode active. Review threat logs periodically for accuracy."
        elif mode == "Semi-Autonomous":
            if pending > 0:
                return f"⚠️ {pending} actions pending review. Please review them in Defense Actions tab."
            else:
                return "No pending approvals. System is handling low-threat events automatically."
        else:  # Manual
            if pending > 0:
                return f"🚨 {pending} actions waiting for your approval. Immediate attention required!"
            else:
                return "Manual mode active. All threats require your approval when detected."
    
    def render_sidebar(self):
        """Render sidebar controls"""
        with st.sidebar:
            st.markdown("🛡️", unsafe_allow_html=True)
            st.markdown("<h2 style='text-align: center;'>Control Panel</h2>", unsafe_allow_html=True)
            
            st.subheader("⚙️ System Controls")
            
            simulation_speed = st.slider(
                "Simulation Speed", 
                min_value=1, 
                max_value=10, 
                value=st.session_state.simulation_speed,
                help="1 = Slow, 10 = Fast"
            )
            st.session_state.simulation_speed = simulation_speed
            
            auto_refresh = st.checkbox("🔄 Auto Refresh", value=st.session_state.auto_refresh)
            st.session_state.auto_refresh = auto_refresh
            
            show_alerts = st.checkbox("🔔 Show Alerts", value=st.session_state.show_alerts)
            st.session_state.show_alerts = show_alerts
            
            st.divider()
            
            st.subheader("🛡️ Defense Settings")
            
            threat_threshold = st.slider(
                "Threat Threshold", 
                min_value=0.1, 
                max_value=1.0, 
                value=st.session_state.threat_threshold,
                step=0.05,
                help="Minimum threat score to trigger defense actions"
            )
            st.session_state.threat_threshold = threat_threshold
            
            # Response mode selection with live update
            new_action_mode = st.selectbox(
                "Response Mode",
                ["Autonomous", "Semi-Autonomous", "Manual"],
                index=["Autonomous", "Semi-Autonomous", "Manual"].index(st.session_state.action_mode),
                help="""
                - Autonomous: AI handles all threats automatically
                - Semi-Autonomous: Auto-handles low threats, requires approval for high threats
                - Manual: All threats require human approval
                """
            )
            
            if new_action_mode != st.session_state.action_mode:
                st.session_state.action_mode = new_action_mode
                # Reset metrics when changing modes
                st.session_state.system_metrics['auto_responses'] = 0
                st.session_state.system_metrics['manual_approvals'] = 0
                st.session_state.system_metrics['pending_reviews'] = 0
                st.session_state.pending_actions = []
                if st.session_state.show_alerts:
                    st.toast(f"🔄 Response mode changed to {new_action_mode}", icon="⚙️")
                st.rerun()
            
            st.divider()
            
            st.subheader("🚀 Quick Actions")
            
            col1, col2 = st.columns(2)
            
            with col1:
                if st.button("🔄 Retrain Model", use_container_width=True, key="retrain_button"):
                    with st.spinner("Retraining AI model..."):
                        time.sleep(2)
                        st.session_state.system_metrics['model_confidence'] = random.uniform(92, 98)
                        st.toast("✅ Model retrained successfully!", icon="✅")
                        st.rerun()
            
            with col2:
                if st.button("📊 Export Report", use_container_width=True, key="export_button"):
                    st.toast("📊 Generating security report...", icon="📊")
                    time.sleep(1.5)
                    st.toast("✅ Report ready for download!", icon="✅")
            
            # Approve all pending actions button (only for Semi-Autonomous and Manual)
            if st.session_state.action_mode in ["Semi-Autonomous", "Manual"] and st.session_state.pending_actions:
                if st.button("✅ Approve All Pending", type="primary", use_container_width=True, key="approve_all"):
                    for i in range(len(st.session_state.pending_actions) - 1, -1, -1):
                        self.approve_action(i)
                    st.toast(f"✅ Approved all {len(st.session_state.pending_actions)} pending actions", icon="✅")
                    st.rerun()
            
            if st.button("🚨 Emergency Lockdown", type="secondary", use_container_width=True, key="lockdown_button"):
                st.error("⚠️ EMERGENCY LOCKDOWN INITIATED!")
                st.warning("All non-essential services suspended")
                # Switch to manual mode for emergency
                st.session_state.action_mode = "Manual"
                st.toast("System switched to Manual mode for emergency", icon="🚨")
                time.sleep(1)
            
            st.divider()
            
            st.subheader("ℹ️ System Information")
            st.write(f"**Version:** 2.1.0")
            st.write(f"**Status:** 🟢 Operational")
            st.write(f"**Response Mode:** {st.session_state.action_mode}")
            st.write(f"**Uptime:** {random.randint(99, 100)}.{random.randint(0, 99):02d}%")
            
            st.divider()
            
            st.subheader("📊 Data Summary")
            st.write(f"Events: {st.session_state.system_metrics['total_events']:,}")
            st.write(f"Threats: {st.session_state.system_metrics['threats_detected']:,}")
            st.write(f"Auto Responses: {st.session_state.system_metrics['auto_responses']}")
            st.write(f"Manual Approvals: {st.session_state.system_metrics['manual_approvals']}")
            st.write(f"Pending Reviews: {st.session_state.system_metrics['pending_reviews']}")
            
            if st.session_state.system_metrics['threats_detected'] > 0:
                accuracy = (st.session_state.system_metrics['true_positives'] / st.session_state.system_metrics['threats_detected']) * 100
                st.write(f"Accuracy: {accuracy:.1f}%")
    
    def run(self):
        """Run the main dashboard loop"""
        
        # Initialize session state
        self.initialize_session_state()
        
        # Generate initial data if empty
        if len(st.session_state.events_data) == 0:
            with st.spinner("🛡️ Initializing Adaptive NeuroDefense System..."):
                for i in range(25):
                    self.update_data()
                    time.sleep(0.05)
            st.success("✅ System initialized successfully!")
            st.rerun()
        
        # Render sidebar
        self.render_sidebar()
        
        # Render header
        self.render_header()
        
        # Render response mode indicator
        self.render_response_mode_indicator()
        
        # Render metrics
        self.render_metrics()
        
        # System health
        self.render_system_health()
        
        # Create tabs
        tab1, tab2, tab3, tab4 = st.tabs([
            "📈 Real-time Monitoring", 
            "🔮 Threat Prediction", 
            "🛡️ Defense Actions", 
            "🤖 AI Insights"
        ])
        
        with tab1:
            col1, col2 = st.columns([2, 1])
            
            with col1:
                self.render_threat_timeline()
            
            with col2:
                self.render_attack_distribution()
            
            self.render_recent_events()
        
        with tab2:
            self.render_prediction_interface()
        
        with tab3:
            self.render_defense_actions()
        
        with tab4:
            self.render_insights_panel()
        
        # Auto-refresh logic - but SKIP when prediction results are showing
        if st.session_state.auto_refresh:
            # Check if we should pause auto-refresh when prediction results are showing
            should_pause = False
            
            # Pause if prediction results are recent (within last 5 seconds)
            if st.session_state.prediction_result is not None:
                time_since_prediction = (datetime.now() - st.session_state.prediction_timestamp).total_seconds() if st.session_state.prediction_timestamp else 999
                if time_since_prediction < 10:  # Pause for 10 seconds after prediction
                    should_pause = True
            
            # Pause if batch results are recent
            if st.session_state.batch_result is not None and not should_pause:
                if hasattr(st.session_state, 'batch_result') and st.session_state.batch_result:
                    time_since_batch = (datetime.now() - st.session_state.batch_result['timestamp']).total_seconds() if 'timestamp' in st.session_state.batch_result else 999
                    if time_since_batch < 10:
                        should_pause = True
            
            if not should_pause:
                current_time = datetime.now()
                time_diff = (current_time - st.session_state.last_update).total_seconds()
                
                # Update interval based on simulation speed
                update_interval = 3 / (st.session_state.simulation_speed / 5)
                
                if time_diff > update_interval:
                    new_event = self.update_data()
                    
                    # Show alerts for high severity threats based on response mode
                    if st.session_state.show_alerts:
                        if new_event['severity'] == 'HIGH':
                            if new_event['requires_approval']:
                                st.toast(
                                    f"🚨 HIGH SEVERITY (Requires Approval): {new_event['attack_type'].upper()} attack from {new_event['source_ip']}",
                                    icon="⚠️"
                                )
                            else:
                                st.toast(
                                    f"🚨 HIGH SEVERITY: {new_event['attack_type'].upper()} attack from {new_event['source_ip']} - Auto-{new_event['action']}",
                                    icon="🚨"
                                )
                        elif new_event['severity'] == 'MEDIUM' and new_event['requires_approval']:
                            st.toast(
                                f"⚠️ Medium threat requires approval: {new_event['attack_type']} from {new_event['source_ip']}",
                                icon="🔍"
                            )
                    
                    st.session_state.last_update = current_time
                    st.rerun()
        
        # Footer
        st.markdown("---")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.caption(f"🖥️ CPU: {st.session_state.system_metrics['cpu_usage']:.1f}%")
        
        with col2:
            st.caption(f"💾 Memory: {st.session_state.system_metrics['memory_usage']:.1f}%")
        
        with col3:
            st.caption(f"📶 Network: {st.session_state.system_metrics['network_traffic']:,} Mbps")

def main():
    """Main function to run the Streamlit app"""
    dashboard = AdaptiveNeuroDefenseDashboard()
    dashboard.run()

if __name__ == "__main__":
    main()