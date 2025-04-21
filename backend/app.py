from flask import Flask, render_template, request, jsonify
import socket
import threading
import time
import platform
import psutil
import plotly
import plotly.graph_objs as go
import json
from datetime import datetime
import subprocess
from scapy.all import sniff, IP, TCP, UDP

app = Flask(__name__)
packet_queue = []
packet_buffer = []
packet_buffer_lock = threading.Lock()
MAX_PACKET_BUFFER = 100

# Store network data history
network_history = {
    'timestamps': [],
    'bytes_sent': [],
    'bytes_recv': []
}

# Store active connections
active_connections = []

def get_network_info():
    """Get basic network interface information without using netifaces"""
    interfaces = {}
    
    # Get all network interfaces using psutil
    net_if_addrs = psutil.net_if_addrs()
    
    for interface_name, addresses in net_if_addrs.items():
        interfaces[interface_name] = {
            'ip': 'Not available',
            'netmask': 'Not available',
            'mac': 'Not available'
        }
        
        # Extract IP, netmask and MAC from addresses
        for addr in addresses:
            if addr.family == socket.AF_INET:  # IPv4
                interfaces[interface_name]['ip'] = addr.address
                interfaces[interface_name]['netmask'] = addr.netmask
            elif addr.family == psutil.AF_LINK:  # MAC
                interfaces[interface_name]['mac'] = addr.address
    
    return interfaces

def get_active_connections():
    """Get list of active network connections"""
    connections = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'ESTABLISHED':
            try:
                process = psutil.Process(conn.pid) if conn.pid else None
                connections.append({
                    'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                    'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                    'status': conn.status,
                    'process': process.name() if process else "Unknown",
                    'pid': conn.pid if conn.pid else "N/A"
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    
    return connections

def monitor_network():
    """Background thread to monitor network usage"""
    last_io = psutil.net_io_counters()
    
    while True:
        time.sleep(1)
        io = psutil.net_io_counters()
        
        # Record the network stats
        now = datetime.now().strftime('%H:%M:%S')
        network_history['timestamps'].append(now)
        network_history['bytes_sent'].append(io.bytes_sent - last_io.bytes_sent)
        network_history['bytes_recv'].append(io.bytes_recv - last_io.bytes_recv)
        
        # Keep the history to the last 60 data points
        if len(network_history['timestamps']) > 60:
            network_history['timestamps'] = network_history['timestamps'][-60:]
            network_history['bytes_sent'] = network_history['bytes_sent'][-60:]
            network_history['bytes_recv'] = network_history['bytes_recv'][-60:]
        
        last_io = io
        
        # Update active connections
        global active_connections
        active_connections = get_active_connections()

# Start the monitoring thread
monitor_thread = threading.Thread(target=monitor_network, daemon=True)
monitor_thread.start()

@app.route('/')
def index():
    """Render main dashboard"""
    network_interfaces = get_network_info()
    system_info = {
        'hostname': socket.gethostname(),
        'platform': platform.platform(),
        'cpu_count': psutil.cpu_count(),
        'cpu_percent': psutil.cpu_percent(interval=0.1),
        'memory': {
            'total': round(psutil.virtual_memory().total / (1024 * 1024 * 1024), 2),  # GB
            'used_percent': psutil.virtual_memory().percent
        }
    }
    
    return render_template("index.html", 
                          interfaces=network_interfaces,
                          system_info=system_info)

@app.route('/network_data')
def network_data():
    """Return JSON data for network graph"""
    return jsonify(network_history)

@app.route('/active_connections')
def connections():
    """Return active connection data"""
    return jsonify(active_connections)

@app.route('/port_scan', methods=['POST'])
def port_scan():
    """Perform a simple port scan"""
    target = request.form.get('target', '127.0.0.1')
    start_port = int(request.form.get('start_port', 1))
    end_port = int(request.form.get('end_port', 1024))
    
    # Limit the range to avoid excessive scanning
    if end_port - start_port > 1000:
        end_port = start_port + 1000
    
    open_ports = []
    
    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)
        result = sock.connect_ex((target, port))
        if result == 0:
            try:
                service = socket.getservbyport(port)
            except:
                service = "unknown"
            open_ports.append({'port': port, 'service': service})
        sock.close()
    
    return jsonify(open_ports)

@app.route('/ping', methods=['POST'])
def ping_host():
    """Ping a host and return results"""
    host = request.form.get('host', '8.8.8.8')
    ping_count = min(int(request.form.get('count', 4)), 10)  # Limit to 10 pings
    
    if platform.system().lower() == "windows":
        ping_cmd = f"ping -n {ping_count} {host}"
    else:
        ping_cmd = f"ping -c {ping_count} {host}"
    
    try:
        result = subprocess.run(ping_cmd, shell=True, capture_output=True, text=True)
        return jsonify({
            'success': True,
            'output': result.stdout
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/generate_graph')
def generate_graph():
    """Generate and return a Plotly graph"""
    # Create a line chart for network traffic
    sent_trace = go.Scatter(
        x=network_history['timestamps'],
        y=network_history['bytes_sent'],
        name='Bytes Sent',
        line=dict(color='#3498db', width=2)
    )
    
    recv_trace = go.Scatter(
        x=network_history['timestamps'],
        y=network_history['bytes_recv'],
        name='Bytes Received',
        line=dict(color='#2ecc71', width=2)
    )
    
    layout = go.Layout(
        title='Network Traffic',
        xaxis=dict(title='Time'),
        yaxis=dict(title='Bytes'),
        template='plotly_dark',
        margin=dict(l=40, r=40, t=40, b=40),
        height=300
    )
    
    fig = go.Figure(data=[sent_trace, recv_trace], layout=layout)
    
    # Create the JSON representation of the graph
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    return graphJSON



def packet_capture_thread():
    def packet_callback(packet):
        if IP in packet:
            with packet_buffer_lock:
                # Format: timestamp, length, src, dst, protocol
                packet_info = {
                    'time': datetime.now().strftime('%H:%M:%S.%f')[:-3],
                    'length': len(packet),
                    'src': packet[IP].src,
                    'dst': packet[IP].dst,
                    'protocol': packet[IP].proto
                }
                
                # Map IP protocol numbers to names
                proto_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
                packet_info['protocol'] = proto_map.get(packet_info['protocol'], 
                                                       str(packet_info['protocol']))
                
                packet_buffer.append(packet_info)
                
                # Keep buffer size limited
                if len(packet_buffer) > MAX_PACKET_BUFFER:
                    packet_buffer.pop(0)
    
    try:
        # Start capturing packets (timeout=1 means check for thread exit every 1 second)
        sniff(prn=packet_callback, store=0, timeout=1)
    except Exception as e:
        print(f"Packet capture error: {e}")

# Start packet capture in a separate thread
capture_thread = threading.Thread(target=packet_capture_thread, daemon=True)
capture_thread.start()



@app.route('/generate_packet_graph')
def generate_packet_graph():
    with packet_buffer_lock:
        # Get the latest packets from the buffer (up to 100)
        packets = packet_buffer[-100:]
    
    # Extract data for each column
    times = [p['time'] for p in packets]
    #lengths = [p['length'] for p in packets]
    #sources = [p['src'] for p in packets]
    #destinations = [p['dst'] for p in packets]
    #protocols = [p['protocol'] for p in packets]

    tcp_packets = [p['length'] if p['protocol'] == 'TCP' else 0 for p in packets]
    udp_packets = [p['length'] if p['protocol'] == 'UDP' else 0 for p in packets]
    icmp_packets = [p['length'] if p['protocol'] == 'ICMP' else 0 for p in packets]
    other_packets = [p['length'] if p['protocol'] not in ['TCP', 'UDP', 'ICMP'] else 0 for p in packets]
    
    # Create Plotly compatible data structure for packet data table
    tcp_trace = go.Scatter(
        x= times,
        y=tcp_packets,
        name='TCP Packets',
        line=dict(color='#3498db', width=2)
    )
    

    udp_trace = go.Scatter(
            x=times,
            y=udp_packets,
        name='UDP Packets',
        line=dict(color='#2ecc71', width=2)

    )
    
    icmp_trace = go.Scatter(
        x=times,
        y=icmp_packets,
        name='ICMP packets',
        line=dict(color='#2ecf71', width=2)
    )

    other_trace = go.Scatter(
        x =times,
        y=other_packets,
        name = 'Other packets',
        line = dict(color = '#2ecf34',width = 2)
    )

    layout = go.Layout(
        title='Packet Graph',
        xaxis=dict(title='Time'),
        yaxis=dict(title='Protocol'),
        template='plotly_dark',
        margin=dict(l=40, r=40, t=40, b=40),
        height=300
    )
    fig = go.Figure(data=[tcp_trace,udp_trace,icmp_trace,other_trace], layout=layout)
    
    # Create the JSON representation of the graph
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    return graphJSON

@app.route('/test')
def test():
    return "Flask server is running!"

if __name__ == '__main__':
    app.run(debug=True)