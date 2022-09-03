about = '''
Script Purpose: Final Project - Simple Network Intrusion Detection System (NIDS)
Script Version: 1.0 May 2021
Script Author:  Gabriel Haab, University of Arizona

Script Revision History:
Version 1.0 February 2021, Python 3.8.2


The purpose of this project is to provide a quick Python script to monitor network traffic on a host and generate potential alerts based on threat lists of known malicious IPs. In other words, this script is a simple network intrusion detection system (NIDS). 
The script collects network packets in real-time and plots the data into the graphs on the left side. The refresh rate is set to 10 seconds. 

Please put your local IP on line 54 under the variable "host" 
'''

Final = """
==================================================
__  ____/ \/ /__  __ )_ |  / /_  // /__  /_  // /
_  /    __  /__  __  |_ | / /_  // /__  /_  // /_
/ /___  _  / _  /_/ /__ |/ / /__  __/  / /__  __/
\____/  /_/  /_____/ _____/    /_/  /_/    /_/   
                                                 
______________              ______               
___  ____/__(_)____________ ___  /               
__  /_   __  /__  __ \  __ `/_  /                
_  __/   _  / _  / / / /_/ /_  /                 
/_/      /_/  /_/ /_/\__,_/ /_/                  
==================================================                                        
"""
      
# Import 3rd Part Libraries
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

import requests
from threading import Thread
import socket

import tkinter.scrolledtext as scrolledtext
import tkinter as tk
from   tkinter import messagebox

import binascii
import struct
import time
from datetime import datetime

from ctypes import *
import re
import random

# This is the IP of the host running the script.
host = "192.168.1.123"

# List of malicious IP (Statically added)
malicious_ip = ['192.168.0.100','192.168.0.60','224.0.0.251','224.0.0.252']
alerts_queue = []
false_positive_queue = []

pd.set_option('display.max_rows', None)
df1 = pd.DataFrame(columns=['Protocol','src_address','dst_address','Time'])

alert_num = 1

'''
This class is responsible for parsing the network packet

'''
class IP(Structure):
    _fields_ = [("ihl",c_ubyte,4),("version",c_ubyte,4),("tos",c_ubyte),("len",c_ushort),("id",c_ushort),("offset",c_ushort),("ttl",c_ubyte),("protocol_num", c_ubyte),("sum",c_ushort),("src",c_uint32),("dst",c_uint32)]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)
    
    def __init__(self, socket_buffer=None):
        # map protocol constants to their names
        self.protocol_map = {
            1:  'ICMP',
            2:  'IGMP',
            6:  'TCP',
            17: 'UDP'
        }
        
        # human readable IP addresses
        self.src_address = socket.inet_ntoa(struct.pack("@I",self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("@I",self.dst))
        
        # human readable protocol
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)  
      
'''
This function is responsible for detection any malicious IP in the network traffic. 
If there is a match on a malicious IP, this function generates an alert. This is a 
recursive function that runs every 10 seconds.
'''
def search_malicious_activity():
    if len(alerts_queue) < 4: 
        for ip in malicious_ip:
            if df1.isin([ip]).any().any():
                if len(alerts_queue) < 4:
                    if (ip not in alerts_queue) and (ip not in false_positive_queue): 
                        generate_alert(ip)
                        alerts_queue.append(ip)
    
    root.after(10000, search_malicious_activity) # every 10 seconds...
'''
This function is responsible for generating the alerts 
in the main tkinter frame. It only generates 
'''
def generate_alert(Alert_IP):
    global alert_num
    if Alert_IP == "TEST":
        Alert_IP = random.choice(malicious_ip)

    single_alert_frame = tk.Frame(alerts_frame, highlightbackground="black", highlightthickness=1)
    single_alert_frame.grid(row=alert_num,column=3, pady= 15)
    text_label = tk.Label(single_alert_frame, text="Malicious IP: \n" + Alert_IP, font=("Helvetica 16 bold"))
    Button_FP = tk.Button(single_alert_frame, text="False Positive", font=("Helvetica 13 bold"), command=lambda: false_positive(single_alert_frame,Alert_IP))
    Button_Investigate = tk.Button(single_alert_frame, text="Investigate", font=("Helvetica 13 bold"), command=lambda: investigateIP(Alert_IP))
    
    text_label.grid(row=0, columnspan=2, pady=10,padx=10)
    Button_FP.grid(row=1, column=1, pady=10,padx=10)
    Button_Investigate.grid(row=1, column=0, pady=10, padx=10)
    alert_num += 1
    root.update()
'''
This function is responsible for closing the alert 
and adding the IP to a whitelist. 
'''
def false_positive(single_alert_frame,Alert_IP):
    single_alert_frame.destroy()
    try:
        alerts_queue.remove(Alert_IP)
        false_positive_queue.append(Alert_IP)
    except:
        pass
    
'''
Default "About" menu for Tkinter.
'''
def menuAbout():
    messagebox.showinfo("About", about)
    messagebox.Dialog
    
'''
This function is responsible for drawing the data based on the collected data
'''
def Draw():
    global df1   
    '''
    Generates the first "donut" graph with the protocols.
    '''
    try:
        figure1 = plt.Figure(figsize=(4,3), dpi=100)
        ax1 = figure1.add_subplot(111)
        ax1.axis('equal')
        bar1 = FigureCanvasTkAgg(figure1, RealTime_frame)
        bar1.get_tk_widget().grid(row=1,column=0)
        df2 = df1['Protocol'].value_counts()
        df2.plot.pie(ax=ax1, wedgeprops=dict(width=0.5), startangle=-40)
        ax1.set_title('Protocol Count')
    except Exception as err :
        pass    
    '''
    Generates the second Graph, which is a count of 
    packets based on the source IP
    '''
    try:
        figure2 = plt.Figure(figsize=(4,3), dpi=100)
        figure2.subplots_adjust(bottom=0.2)
        figure2.subplots_adjust(left=0.2)
        ax2 = figure2.add_subplot(111)
        bar2 = FigureCanvasTkAgg(figure2, RealTime_frame)
        bar2.get_tk_widget().grid(row=1,column=1)
        df2 = df1['src_address'].value_counts().head(5)
        df2.plot(kind='bar', legend=True, ax=ax2, rot=13)
        ax2.set_title('Source Address Count (Top 5)')
    except Exception as err :
        pass
    '''
    Generates the third Graph, which is a count of 
    packets based on the destination IP
    '''    
    try:
        figure3 = plt.Figure(figsize=(4,3), dpi=100)
        figure3.subplots_adjust(bottom=0.2)
        figure3.subplots_adjust(left=0.2)
        ax3 = figure3.add_subplot(111)
        bar3 = FigureCanvasTkAgg(figure3, RealTime_frame)
        bar3.get_tk_widget().grid(row=1,column=2)
        df2 = df1['dst_address'].value_counts().head(5)
        df2.plot(kind='bar', legend=True, ax=ax3,rot=13)
        ax3.set_title('Destination Address Count (Top 5)')   
    except Exception as err :
        pass    
    '''
    Generates the fourth graph, which is the count of packets detected 
    per minute.  
    '''
    try:
        figure4 = plt.Figure(figsize=(12,3), dpi=100)
        figure3.subplots_adjust(bottom=0.2)
        ax4 = figure4.add_subplot(111)
        line2 = FigureCanvasTkAgg(figure4, RealTime_frame)
        line2.get_tk_widget().grid(row=2,columnspan=3)
        df2 = df1.resample(rule='1min', on='Time', offset='1min').count().tail(10)
        df2 = df2['Time']
        df2.plot(kind='line', legend=True, ax=ax4, color='r',marker='o', fontsize=8)
        ax4.set_title('Data History ') 
    except Exception as err:
        pass      

'''
This function is responsible for refreshing the previously generated graphs, 
based on the current data saved in the pandas dataframe. It also saves the pickle
file for future use. This is a recursive function that runs every 10 seconds. 
'''
def Refresher():
    Draw()
    df1.to_pickle("./Pandas_NetworkDump.pkl")
    root.after(10000, Refresher) # every 10 seconds...

'''
This is the function that searchs for a specific IP in the dataframe, and 
prints every row that the script shows up. It generates a window and display
all the information in a scrolled box. 
'''
def investigateIP(query_string):
    window = tk.Toplevel(root)
    window.resizable(False, False)
    window.title('Results')
    
    results_box_label = tk.Label(window, text="Results for: " + query_string, font=("Helvetica 16 bold"))
    results_box = tk.scrolledtext.ScrolledText(window, height=30, width=200)  # Create the TextBox
    closebtn = tk.Button(window, text='Close', command=lambda: window.destroy(), font=("Helvetica 16 bold"), width=20)

    results_box_label.grid(row=0, columnspan=2, padx=5, pady=5)
    results_box.grid(row=1, columnspan=2, padx=5, pady=5)
    closebtn.grid(row=2, columnspan=2, padx=5, pady=5)

    is_source = df1['src_address'] == query_string
    is_destination = df1['dst_address'] == query_string
    
    is_source_data = df1[is_source]
    is_destination_data = df1[is_destination]
    
    if is_source_data.empty:
        pass
    else:
        results_box.insert(tk.END, is_source_data)

    if is_destination_data.empty:
        pass
    else:
        results_box.insert(tk.END, is_destination_data)
    
    if is_destination_data.empty and is_source_data.empty:
        results_box.insert(tk.END, "No packet found")

'''
This function starts a thread for the function "start_capture".
'''
def capture_thread():
    threads = []
    t = Thread(target=start_capture)
    threads.append(t)
    t.setDaemon(True)
    t.start() 

'''
This function is responsible for starting the network capture.
'''
def start_capture():
    global df1
    try:
        s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_IP)
        # 'host' is the local IP of the host to bind.  
        s.bind((host,0))
        s.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
        s.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)
        
        # Start capturing the packets
        while True:
            raw_buffer = s.recvfrom(65535)[0]            
            ip_header = IP(raw_buffer[0:20])
            # Append de data to the dataframe. 
            # Protocol | Source Address | Destination Address | Time 
            df1 = df1.append({'Protocol': ip_header.protocol, 'src_address': ip_header.src_address, 'dst_address': ip_header.dst_address, 'Time': datetime.now() }, ignore_index=True)     
            #print("Protocol: %s %s -> %s %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address, time.asctime()))
            
    except Exception as err:
        if "forbidden" in str(err):
            print("Please run the script using privilege mode to capture data")
        else:
            print("*** ERROR *** :" + str(err))
            print(raw_buffer)
'''
This function connects to the website "projecthoneypot" and using regex, 
extracts all IP addresses noted as malicious by the website. The IPs 
are appended to the previously declared list of malicious ip. 
'''
def get_malicious_list():
    global malicious_ip
    url = "https://www.projecthoneypot.org/list_of_ips.php"
    data = requests.get(url)
    
    ip_list = re.findall('(?:[0-9]{1,3}\.){3}[0-9]{1,3}', data.text)
    for ip in ip_list: 
        if ip not in malicious_ip:
            malicious_ip.append(ip)
    pass 

# Main Program Starts Here
#===================================
'''
This is the main function, which is responsible for generating the 
tkinter window which is dividded into 2 frames (Graphs and alerts)
'''
def main():
    global root
    global alerts_frame
    global RealTime_frame
    root = tk.Tk()
    root.title('Simple Network Intrusion Detection System (SNIDS)')
    root.resizable(False, False)
    menuBar = tk.Menu(root)
    toolsMenu = tk.Menu(menuBar, tearoff=0)
    
    toolsMenu.add_command(label='About SNIDS', command=menuAbout, underline=0)
    toolsMenu.add_command(label='Generate Test Alert', command=lambda: generate_alert("TEST"), underline=0)
    toolsMenu.add_separator()
    toolsMenu.add_command(label='Exit', command=root.destroy)
    menuBar.add_cascade(label='Help', menu=toolsMenu, underline=0)  
    root.config(menu=menuBar)  # menu ends    
    
    RealTime_frame = tk.Frame(root, highlightbackground="black", highlightthickness=1)
    RealTime_frame.grid(row=1,column=0, padx=10, pady=10) 
    
    alerts_frame = tk.Frame(root)
    alerts_frame.grid(row=1,column=1)
    
    alerts_Label = tk.Label(root, text="Alerts", font=("Helvetica 16 bold"), padx=150)
    Data_Label = tk.Label(root, text="Real Time Data (Refresh rate = 10 Seconds)", font=("Helvetica 16 bold"), pady=20)
    
    alerts_Label.grid(row=0,column=1)
    Data_Label.grid(row=0,column=0)
    
    Draw()
    Refresher()
    search_malicious_activity()
    root.mainloop()
    pass

"""
Script starts here. 
It reads the pickle file and add the information 
to the current dataframe. 
"""
if __name__ == '__main__':
    try:
        df1 = pd.read_pickle("./Pandas_NetworkDump.pkl")
    except:
        print("Unable to load pickle file")
        
    print(Final)
    get_malicious_list()
    capture_thread()
    main()