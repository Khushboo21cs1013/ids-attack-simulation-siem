import matplotlib
matplotlib.use('Agg')  
import sqlite3
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import io
import base64
from flask import Flask, render_template, redirect, url_for, request, session

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Route for login
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == 'admin' and password == 'admin':
            session['user'] = username
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Invalid username or password')
    return render_template('login.html')

# Route for logging out
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

# Route for the dashboard
@app.route('/dashboard')
def dashboard():
    alerts, alert_stats, scans, scan_stats = fetch_data()
    alert_chart = generate_alert_chart(alert_stats)
    scan_chart = generate_scan_chart(scan_stats)
    ids_logs, log_heatmap = fetch_ids_logs()  # Fetch IDS logs and heatmap data
    return render_template('dashboard.html', alerts=alerts, alert_chart=alert_chart, scan_chart=scan_chart, ids_logs=ids_logs, log_heatmap=log_heatmap)

# Fetching data from SQLite
def fetch_data():
    conn = sqlite3.connect('D:/Visual Studio Code/Security/IDS/ids.db')
    c = conn.cursor()

    # Fetch alert data
    c.execute("SELECT timestamp, severity, alert_type, message FROM alerts ORDER BY timestamp DESC")
    alerts = c.fetchall()

    # Fetch alert statistics
    c.execute("SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity ORDER BY count DESC")
    alert_stats = c.fetchall()

    # Fetch scan data
    c.execute("SELECT timestamp, file_path, hash, scan_result FROM scans ORDER BY timestamp DESC")
    scans = c.fetchall()

    # Fetch scan statistics
    c.execute("SELECT scan_result, COUNT(*) as count FROM scans GROUP BY scan_result ORDER BY count DESC")
    scan_stats = c.fetchall()

    conn.close()
    return alerts, alert_stats, scans, scan_stats

# Generating alert chart
def generate_alert_chart(alert_stats):
    severities, counts = zip(*alert_stats)
    fig, ax = plt.subplots(figsize=(5, 4))
    ax.bar(severities, counts)
    ax.set_title('Alert Statistics by Severity')
    ax.set_xlabel('Severity')
    ax.set_ylabel('Count')
    chart = get_chart(fig)
    return chart

# Generating scan result chart
def generate_scan_chart(scan_stats):
    results, counts = zip(*scan_stats)
    fig, ax = plt.subplots(figsize=(5, 4))
    ax.pie(counts, labels=results, autopct='%1.1f%%')
    ax.set_title('Scan Results Distribution')
    chart = get_chart(fig)
    return chart

# Convert chart to base64 for embedding in HTML
def get_chart(fig):
    buf = io.BytesIO()
    fig.savefig(buf, format='png')
    data = base64.b64encode(buf.getbuffer()).decode('ascii')
    return data

# Fetch IDS logs and generate heatmap data
def fetch_ids_logs():
    log_file_path = 'D:/Visual Studio Code/Security/IDS/ids.log'  # Change this to your log file's actual path
    try:
        with open(log_file_path, 'r') as file:
            logs = file.readlines()
        
        # Example: Generate a heatmap or graphical plot from logs
        log_data = parse_logs(logs)
        heatmap_data = generate_heatmap(log_data)
        
        return ''.join(logs), heatmap_data
    except Exception as e:
        return f"Error reading logs: {str(e)}", None

# Parse logs to DataFrame
def parse_logs(logs):
    log_entries = []
    for line in logs:
        parts = line.split(" - ")
        if len(parts) > 2:
            # Extract timestamp and alert message
            timestamp = parts[0].strip()
            message = parts[2].strip()

            # Only include logs with the alert message
            if "Alert email sent" in message:
                alert_type = message.split(":")[1].strip()  # Extract specific alert type
                try:
                    # Convert the timestamp string to a datetime object for easier manipulation
                    timestamp = pd.to_datetime(timestamp, format='%Y-%m-%d %H:%M:%S,%f')
                    log_entries.append([timestamp, alert_type])
                except ValueError:
                    continue  # Skip logs with an invalid timestamp format
    
    # Convert the log entries to a DataFrame
    df = pd.DataFrame(log_entries, columns=["timestamp", "alert_type"])

    # Group by timestamp for a heatmap representation (optional)
    df['hour'] = df['timestamp'].dt.hour  # Add an 'hour' column for time grouping
    df['minute'] = df['timestamp'].dt.minute  # Add minute if you want more detailed intervals
    
    return df

# Generate heatmap from log data
def generate_heatmap(log_data):
    if log_data.empty:
        return None  # Return None if no data available for heatmap generation
    
    # Create a pivot table to show alert frequency by hour and minute
    pivot_table = pd.pivot_table(log_data, values='alert_type', 
                                 index='hour', columns='minute', aggfunc='count', fill_value=0)

    # Check if pivot_table has data to plot
    if pivot_table.empty:
        return None  # Return None if pivot table has no data
    
    # Generate heatmap if data is available
    fig, ax = plt.subplots(figsize=(6, 4))  # Increased size to 12x8 for a larger heatmap
    sns.heatmap(pivot_table, annot=True, fmt='d', cmap='YlGnBu', ax=ax, cbar_kws={'label': 'Alert Count'})
    heatmap = get_chart(fig)
    return heatmap

# Error handling
@app.errorhandler(Exception)
def handle_exception(e):
    return render_template('error.html', error=str(e)), 500

if __name__ == '__main__':
    app.run(debug=True)
