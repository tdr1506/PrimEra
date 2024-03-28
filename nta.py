import tkinter as tk
from tkinter import filedialog, ttk
from scapy.all import *
import geoip2.database
from collections import Counter

class NetworkAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Analyzer")

        self.geoip_reader_asn = geoip2.database.Reader('MaxMind Databases\GeoLite2-ASN.mmdb')
        self.geoip_reader_city = geoip2.database.Reader('MaxMind Databases\GeoLite2-City.mmdb')
        self.geoip_reader_country = geoip2.database.Reader('MaxMind Databases\GeoLite2-Country.mmdb')   

        # Calculate window size based on screen resolution
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        window_width = int(screen_width * 0.8)
        window_height = int(screen_height * 0.8)
        window_x = (screen_width - window_width) // 2
        window_y = (screen_height - window_height) // 2
        root.geometry(f"{window_width}x{window_height}+{window_x}+{window_y}")

        # Main Frame
        self.main_frame = ttk.Frame(root, padding="10")
        self.main_frame.grid(row=0, column=0, sticky="nsew")

        # File Selection Section
        self.file_frame = ttk.LabelFrame(self.main_frame, text="PCAP File Selection", padding="10")
        self.file_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        self.label = ttk.Label(self.file_frame, text="Select PCAP File:")
        self.label.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)

        self.select_button = ttk.Button(self.file_frame, text="Browse", command=self.browse_file)
        self.select_button.grid(row=0, column=1, padx=5, pady=5)

        self.analyze_button = ttk.Button(self.file_frame, text="Analyze", command=self.analyze_pcap)
        self.analyze_button.grid(row=0, column=2, padx=5, pady=5)

        # Clear and Export Buttons
        self.clear_button = ttk.Button(self.file_frame, text="Clear", command=self.clear_output)
        self.clear_button.grid(row=0, column=3, padx=5, pady=5)

        self.export_button = ttk.Button(self.file_frame, text="Export", command=self.export_analysis)
        self.export_button.grid(row=0, column=4, padx=5, pady=5)

        # Output Tree
        self.output_tree_frame = ttk.LabelFrame(self.main_frame, text="Packet Information", padding="10")
        self.output_tree_frame.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")

        self.output_tree = ttk.Treeview(self.output_tree_frame, columns=("Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol", "Location"))
        self.output_tree.heading("#0", text="Packet No.", anchor=tk.CENTER)
        self.output_tree.heading("Source IP", text="Source IP", anchor=tk.CENTER)
        self.output_tree.heading("Source Port", text="Source Port", anchor=tk.CENTER)
        self.output_tree.heading("Destination IP", text="Destination IP", anchor=tk.CENTER)
        self.output_tree.heading("Destination Port", text="Destination Port", anchor=tk.CENTER)
        self.output_tree.heading("Protocol", text="Protocol", anchor=tk.CENTER)
        self.output_tree.heading("Location", text="Location", anchor=tk.CENTER)
        self.output_tree.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        self.scrollbar = ttk.Scrollbar(self.output_tree_frame, orient="vertical", command=self.output_tree.yview)
        self.scrollbar.grid(row=0, column=1, sticky="ns")
        self.output_tree.configure(yscrollcommand=self.scrollbar.set)

        # Main Frame
        self.main_analysis_frame = ttk.Frame(root, padding="10")
        self.main_analysis_frame.grid(row=1, column=0, sticky="nsew")
        
        # Analysis Results Section
        self.analysis_results_frame = ttk.LabelFrame(self.main_analysis_frame, text="Analysis Results", padding="10")
        self.analysis_results_frame.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")

        self.analysis_results_text = tk.Text(self.analysis_results_frame, height=10, width=85, wrap="word")
        self.analysis_results_text.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        # Frame Result Analysis
        self.frame_result_frame = ttk.LabelFrame(self.main_analysis_frame, text="Frame Result Analysis", padding="10")
        self.frame_result_frame.grid(row=2, column=0, padx=10, pady=10, sticky="nsew")

        # Remedial Measures Section
        self.remedial_measures_frame = ttk.LabelFrame(self.main_analysis_frame, text="Remedial Measures", padding="10")
        self.remedial_measures_frame.grid(row=1, column=1, padx=10, pady=10, sticky="nsew")

        self.remedial_measures_text = tk.Text(self.remedial_measures_frame, height=10, width=85, wrap="word")
        self.remedial_measures_text.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        self.main_frame.grid_rowconfigure(1, weight=1)
        self.main_frame.grid_rowconfigure(3, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

    def browse_file(self):
        self.file_path = filedialog.askopenfilename(filetypes=[("PCAP Files", "*.pcap"), ("All Files", "*.*")])
        if self.file_path:
            self.label.config(text="Selected File: " + self.file_path)

    def analyze_pcap(self):
        if not hasattr(self, 'file_path'):
            print("Error: Please select a PCAP file first.")
            return

        self.output_tree.delete(*self.output_tree.get_children())  # Clear previous results

        try:
            pkts = rdpcap(self.file_path)
        except Exception as e:
            print("Error reading PCAP file:", e)
            return

        results = []

        for idx, pkt in enumerate(pkts, start=1):
            ip_layer = pkt.getlayer(IP)
            if ip_layer:
                src_ip = getattr(ip_layer, 'src', "")
                dst_ip = getattr(ip_layer, 'dst', "")
                protocol = pkt.sprintf("%IP.proto%") if IP in pkt else ""
                src_port = ""
                dst_port = ""
                if hasattr(pkt.getlayer(IP), 'sport'):
                    src_port = getattr(pkt.getlayer(IP), 'sport', "")
                if hasattr(pkt.getlayer(IP), 'dport'):
                    dst_port = getattr(pkt.getlayer(IP), 'dport', "")

                # Get location if IP is not empty
                location = ""
                if src_ip:
                    location = self.get_geo_location(src_ip)

                # Append results to list
                results.append([src_ip, src_port, dst_ip, dst_port, protocol, location])

        # Display results in the Treeview
        for idx, result in enumerate(results, start=1):
            self.output_tree.insert("", "end", text=str(idx), values=result)

        # Generate analysis report
        total_packets = len(pkts)
        syn_count = sum(1 for pkt in pkts if TCP in pkt and pkt[TCP].flags & 2)
        total_ack_packets = total_packets - syn_count
        attack_type = self.detect_attack_type(syn_count, total_packets)
        top_conversations = self.get_top_conversations(results)
        top_locations = self.get_top_locations(results)

        analysis_report = f"Total Packets Analyzed: {total_packets}\n"
        analysis_report += f"Attack Type: {attack_type}\n"
        analysis_report += f"Total SYN Packets: {syn_count}\n"
        analysis_report += f"Total ACK Packets: {total_ack_packets}\n"
        analysis_report += f"Top Conversations:\n{top_conversations}\n"
        analysis_report += f"Top Locations of Endpoints:\n{top_locations}"

        self.analysis_results_text.delete("1.0", tk.END)
        self.analysis_results_text.insert(tk.END, analysis_report)

        # Display remedial measures
        remedial_measures = self.get_remedial_measures(attack_type)
        self.remedial_measures_text.delete("1.0", tk.END)
        self.remedial_measures_text.insert(tk.END, remedial_measures)

    def get_geo_location(self, ip):
        try:
            response = self.geoip_reader_city.city(ip)
            return f"{response.city.name}, {response.subdivisions.most_specific.name}, {response.country.name}"
        except geoip2.errors.AddressNotFoundError:
            return ""
        except Exception as e:
            print("Error getting geo location:", e)
            return ""

    def detect_attack_type(self, syn_count, total_packets):
        syn_percentage = (syn_count / total_packets) * 100
        if syn_percentage >= 70:
            return "DDoS Attack"
        elif syn_percentage >= 50:
            return "Spoofed Attack"
        elif syn_percentage >= 30:
            return "Direct Attack"
        else:
            return "Normal Traffic"

    def get_top_conversations(self, results):
        conversations = Counter((result[0], result[1], result[2], result[3], result[4]) for result in results)
        top_conversations = "\n".join(f"{k}: {v} packets" for k, v in conversations.most_common(5))
        return top_conversations

    def get_top_locations(self, results):
        locations = Counter(result[5] for result in results if result[5])
        top_locations = "\n".join(f"{k}: {v} packets" for k, v in locations.most_common(5))
        return top_locations

    def get_remedial_measures(self, attack_type):
        # Define remedial measures based on the attack type
        if attack_type == "DDoS Attack":
            return "1. Implement rate limiting on incoming connections.\n2. Use a DDoS mitigation service.\n3. Harden network infrastructure."
        elif attack_type == "Spoofed Attack":
            return "1. Implement source IP verification.\n2. Use ingress and egress filtering.\n3. Monitor and analyze network traffic."
        elif attack_type == "Direct Attack":
            return "1. Implement intrusion detection/prevention systems.\n2. Configure firewalls to block suspicious traffic.\n3. Conduct security audits regularly."
        else:
            return "No specific remedial measures needed for normal traffic."

    def clear_output(self):
        self.output_tree.delete(*self.output_tree.get_children())
        self.analysis_results_text.delete("1.0", tk.END)
        self.remedial_measures_text.delete("1.0", tk.END)

    def export_analysis(self):
        filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if filename:
            with open(filename, 'w') as file:
                file.write(self.analysis_results_text.get("1.0", tk.END))
                file.write("\n\n")
                file.write(self.remedial_measures_text.get("1.0", tk.END))

root = tk.Tk()
app = NetworkAnalyzerApp(root)
root.mainloop()
