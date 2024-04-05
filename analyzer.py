import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext
from tkinter import messagebox
import time
import re

# Function to read log file and extract unique ports
def extract_unique_ports(log_file):
    unique_ports = set()
    with open(log_file, 'r') as file:
        for line in file:
            if 'Connection Received on port:' in line:
                port = line.split('port: ')[1].split(' ')[0]
                unique_ports.add(port)
    return list(unique_ports)

unique_ips = set()  # Set to store unique IP addresses

# Function to update logs and ports periodically
def update_logs_and_ip():
    global last_position, last_ports
    try:
        with open(log_file, 'r') as file:
            file.seek(last_position)
            new_logs = file.readlines()
            last_position = file.tell()

            # Update log_text with new logs
            for line in new_logs:
                if line.startswith('['):  # Check if the line starts with "["
                    parts = line.split('[')
                    timestamp = parts[1].split(']')[0] if len(parts) >= 2 else "NULL"
                    date, time = timestamp.split('T') if timestamp != "NULL" else ("NULL", "NULL")
                    port = parts[2].split(']')[0] if len(parts) >= 3 else "NULL"
                    ipaddress = parts[3].split(']')[0] if len(parts) >= 4 else "NULL"
                    data = parts[4].split(']')[0] if len(parts) >= 5 else "NULL"
                    log_tree.insert("", "end", values=(date, time, port, ipaddress, data))
                    log_text.insert(tk.END, line)
                    
                    # Add unique IP address to the set
                    ip = ipaddress.split(':')[0]
                    # Add unique IP address to the set
                    if ip not in unique_ips:
                        ip_listbox.insert(tk.END, ip)
                        unique_ips.add(ip)

    except Exception as e:
        print(f"An error occurred while updating logs and ip: {str(e)}")

    root.after(1000, update_logs_and_ip)  # Schedule next update after 1 second


# Function to extract port from log entry
def extract_port(log_entry):
    if 'Connection Received on port:' in log_entry:
        return log_entry.split('port: ')[1].split(' ')[0]
    return None

# Create main window
root = tk.Tk()
root.title("Log Analyzer")

# Create a frame for the list of ip
ip_frame = ttk.Frame(root)
ip_frame.grid(column=0, row=0, padx=10, pady=10, sticky=(tk.W, tk.N, tk.S))

# Create a label for the ip panel
ttk.Label(ip_frame, text="IP Address").grid(column=0, row=0, sticky=tk.W, padx=5, pady=5)

# Create a listbox to display unique ip
ip_listbox = tk.Listbox(ip_frame, selectmode=tk.SINGLE, width=15, height=10)
ip_listbox.grid(column=0, row=1, sticky=(tk.W, tk.E), padx=5, pady=5)

# # Create a scrollbar for the log text area
scrollbar = ttk.Scrollbar(root)

# Create a scrolled text widget to display log entries
log_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=100, height=20, yscrollcommand=scrollbar.set)
log_text.grid(column=2, row=1, padx=10, pady=10, sticky=(tk.W, tk.N, tk.S, tk.E))

# Configure the scrollbar to work with the log text widget
scrollbar.config(command=log_text.yview)

# Create a frame for the Treeview and scrollbar
tree_frame = ttk.Frame(root)
tree_frame.grid(column=2, row=0, padx=10, pady=10, sticky=(tk.W, tk.N, tk.S, tk.E))

# Create a Treeview widget to display log entries
log_tree = ttk.Treeview(tree_frame, columns=("Date", "Time", "Port", "IP Address", "Data"), show="headings")
log_tree.heading("Date", text="Date", anchor=tk.W)
log_tree.heading("Time", text="Time", anchor=tk.W)
log_tree.heading("Port", text="Port", anchor=tk.W)
log_tree.heading("IP Address", text="IP Address", anchor=tk.W)
log_tree.heading("Data", text="Data", anchor=tk.W)

# Set the width of each column
log_tree.column("Date", width=100)  # Adjust the width as needed
log_tree.column("Time", width=100)  # Adjust the width as needed
log_tree.column("Port", width=70)   # Adjust the width as needed
log_tree.column("IP Address", width=120)  # Adjust the width as needed
log_tree.column("Data", width=300)  # Adjust the width as needed
log_tree.grid(column=0, row=0, sticky=(tk.W, tk.N, tk.S, tk.E))

# Create a scrollbar for the Treeview widget
tree_scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=log_tree.yview)
tree_scrollbar.grid(column=1, row=0, sticky=(tk.N, tk.S))

# Configure the Treeview widget to work with the scrollbar
log_tree.config(yscrollcommand=tree_scrollbar.set)

# Adjust column weights so that they resize together
tree_frame.columnconfigure(0, weight=1)  # Treeview

# Define the log file
log_file = 'honeypwned.log'

# Initialize variables for tracking log file position and ip
last_position = 0
last_ports = []
port_logs = {}

# Start updating logs and ip periodically
update_logs_and_ip()

# Start the GUI event loop
root.mainloop()
