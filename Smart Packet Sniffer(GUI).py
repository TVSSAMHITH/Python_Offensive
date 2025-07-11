import time
import tkinter as tk
from tkinter import scrolledtext, filedialog, ttk
from scapy.all import sniff, get_if_list, conf
import threading
import json

class PacketsCapture:
    def __init__(self):
        self.app = tk.Tk()
        self.app.title("Smart Packet Sniffer")
        self.app.geometry("1250x800")

        self.packet_count = 0
        self.expanded_states = {}
        self.raw_packets = []
        self.packet_ids = []
        self.stop_capture = False
        self.pause_capture = False
        self.selected_interface = tk.StringVar()

        self.build_ui()
        self.sniff_thread = threading.Thread(target=self.insert_data, daemon=True)
        self.sniff_thread.start()
        self.app.mainloop()

    def build_ui(self):
        tk.Label(self.app, text="Smart Packet Sniffer Pro", font=("Helvetica", 16, "bold")).pack(pady=10)

        control_frame = tk.Frame(self.app)
        control_frame.pack()

        tk.Label(control_frame, text="Interface:").grid(row=0, column=0, padx=5)
        interfaces = get_if_list()
        default_iface = conf.iface
        self.selected_interface.set(default_iface)
        ttk.Combobox(control_frame, values=interfaces, textvariable=self.selected_interface, state="readonly", width=30).grid(row=0, column=1, padx=5)

        tk.Label(control_frame, text="Filter:").grid(row=0, column=2, padx=5)
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", self.apply_filter)
        tk.Entry(control_frame, textvariable=self.filter_var, width=40).grid(row=0, column=3, padx=5)

        self.pause_button = tk.Button(control_frame, text="⏸ Pause", command=self.pause_sniffing, bg="#f1c40f")
        self.pause_button.grid(row=0, column=4, padx=5)

        self.resume_button = tk.Button(control_frame, text="▶ Resume", command=self.resume_sniffing, bg="#2ecc71")
        self.resume_button.grid(row=0, column=5, padx=5)

        self.stop_button = tk.Button(control_frame, text="⏹ Stop", command=self.stop_sniffing, bg="red", fg="white")
        self.stop_button.grid(row=0, column=6, padx=5)

        self.export_button = tk.Button(control_frame, text="💾 Export", command=self.export_packets, bg="#3498db", fg="white")
        self.export_button.grid(row=0, column=7, padx=5)

        self.import_button = tk.Button(control_frame, text="📂 Import", command=self.import_packets, bg="#9b59b6", fg="white")
        self.import_button.grid(row=0, column=8, padx=5)

        self.counter_label = tk.Label(self.app, text="Total Packets: 0", font=("Consolas", 12))
        self.counter_label.pack(pady=5)

        self.data_shown = scrolledtext.ScrolledText(self.app, width=140, height=35, font=("Courier", 10), bg="white", fg="black", insertbackground='black')
        self.data_shown.pack(padx=10, pady=10)
        self.data_shown.config(state=tk.DISABLED)

    def stop_sniffing(self):
        self.stop_capture = True
        self.stop_button.config(state=tk.DISABLED)
        self.pause_button.config(state=tk.DISABLED)
        self.resume_button.config(state=tk.DISABLED)

    def pause_sniffing(self):
        self.pause_capture = True

    def resume_sniffing(self):
        self.pause_capture = False

    def export_packets(self):
        file = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if file:
            with open(file, "w") as f:
                json.dump(self.raw_packets, f)

    def import_packets(self):
        file = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
        if file:
            with open(file, "r") as f:
                self.raw_packets = json.load(f)
            self.expanded_states = {pkt["id"]: False for pkt in self.raw_packets}
            self.packet_ids = [pkt["id"] for pkt in self.raw_packets]
            self.packet_count = len(self.raw_packets)
            self.apply_filter()

    def get_protocol(self, packet):
        if "TCP" in packet:
            return "TCP"
        elif "UDP" in packet:
            return "UDP"
        elif "ICMP" in packet:
            return "ICMP"
        elif "ARP" in packet:
            return "ARP"
        elif "DNS" in packet:
            return "DNS"
        else:
            return "OTHER"

    def get_color(self, proto):
        return {
            "TCP": "#2980b9",
            "UDP": "#27ae60",
            "ICMP": "#e67e22",
            "ARP": "#f39c12",
            "DNS": "#8e44ad",
            "OTHER": "#7f8c8d"
        }.get(proto, "#7f8c8d")

    def packet_capture(self, packet):
        if self.stop_capture:
            return False
        while self.pause_capture:
            time.sleep(0.1)

        self.packet_count += 1
        packet_id = f"pkt_{self.packet_count}"
        timestamp = time.strftime('%H:%M:%S')
        proto = self.get_protocol(packet)
        color = self.get_color(proto)

        summary = f"[{timestamp}] Packet {self.packet_count}: {packet.summary()}\n"
        details = self.get_packet_details(packet)

        self.raw_packets.append({
            "id": packet_id,
            "summary": summary,
            "details": details,
            "protocol": proto,
            "color": color
        })
        self.packet_ids.append(packet_id)
        self.expanded_states[packet_id] = False

        self.apply_filter()
        self.counter_label.config(text=f"Total Packets: {self.packet_count}")

    def get_packet_details(self, packet):
        details = ""
        layer_index = 0
        layer = packet
        try:
            while layer:
                details += f"   [Layer {layer_index}] {layer.name}\n"
                for field_name, field_value in layer.fields.items():
                    value = str(field_value)
                    if len(value) > 100:
                        value = value[:97] + "..."
                    details += f"      ├─ {field_name}: {value}\n"
                layer = layer.payload
                layer_index += 1
                if not layer or layer.name == "NoPayload":
                    break
        except Exception as e:
            details += f"   [!] Error parsing packet: {e}\n"
        details += "\n"
        return details

    def toggle_details(self, packet_id):
        self.expanded_states[packet_id] = not self.expanded_states[packet_id]
        self.apply_filter()

    def apply_filter(self, *args):
        keyword = self.filter_var.get().lower()
        self.data_shown.config(state=tk.NORMAL)
        self.data_shown.delete("1.0", tk.END)

        for packet in self.raw_packets:
            pkt_id = packet["id"]
            summary = packet["summary"]
            details = packet["details"]
            color = packet["color"]

            if keyword in summary.lower() or keyword in details.lower():
                self.data_shown.insert(tk.END, f"\n{'='*100}\n", pkt_id)
                self.data_shown.insert(tk.END, summary, pkt_id)
                self.data_shown.insert(tk.END, f"{'='*100}\n", pkt_id)
                self.data_shown.tag_config(pkt_id, foreground=color)
                self.data_shown.tag_bind(pkt_id, "<Button-1>", lambda e, pid=pkt_id: self.toggle_details(pid))

                if self.expanded_states.get(pkt_id):
                    self.data_shown.insert(tk.END, details, f"{pkt_id}_details")
                    self.data_shown.tag_config(f"{pkt_id}_details", foreground="black")

        self.data_shown.config(state=tk.DISABLED)

    def insert_data(self):
        sniff(prn=self.packet_capture, store=False, iface=self.selected_interface.get())

if __name__ == "__main__":
    PacketsCapture()
