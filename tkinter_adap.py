import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import json
from datetime import datetime
import requests
import hashlib
import base64

class SOCReportGenerator:
    def __init__(self, root):
        self.root = root
        self.root.title("SOC Investigation Report Generator")
        self.root.geometry("1000x700")
        
        # Initialize data structures
        self.api_keys = {
            "virustotal": "",
            "abuseipdb": "",
            "urlscan": "",
            "scamalytics": "",
            "scamalytics_username": ""
        }
        self.entities = {'hosts': [], 'users': []}
        self.tanium_investigations = []
        self.mde_investigations = []
        self.domains_ips = []
        self.queries = []
        
        self.setup_gui()
    
    def setup_gui(self):
        # Create main notebook (tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)

        # Add a button to open the API keys pop-up
        self.api_button = tk.Button(self.root, text="API Keys", bg="#F105BE", fg="black", command=self.open_api_keys_popup)
        self.api_button.pack(side='top', anchor='ne', padx=10, pady=5)
        
        # Tabs
        self.setup_generate_tab()
        self.setup_triage_tab()
        self.setup_entities_tab()
        self.setup_tanium_tab()
        self.setup_mde_tab()
        self.setup_c2_domain_tab()
        self.setup_phishing_tab()
        self.setup_queries_tab()
        self.setup_vmlab_tab()
        self.setup_conclusion_tab()
    
    def open_api_keys_popup(self):
        # Create a new top-level window
        self.api_window = tk.Toplevel(self.root)
        self.api_window.title("API Keys")

        # Create a scrollable frame
        canvas = tk.Canvas(self.api_window)
        scrollbar = ttk.Scrollbar(self.api_window, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        # API Key entries
        api_services = [
            ("VirusTotal API Key:", "virustotal"),
            ("AbuseIPDB API Key:", "abuseipdb"),
            ("URLScan API Key:", "urlscan"),
            ("Scamalytics API Key:", "scamalytics"),
            ("Scamalytics Username:", "scamalytics_username")
        ]

        self.popup_api_entries = {}
        for i, (label_text, key) in enumerate(api_services):
            ttk.Label(scrollable_frame, text=label_text).grid(row=i, column=0, sticky='w', padx=5, pady=5)
            entry = ttk.Entry(scrollable_frame, width=50, show="*" if "username" not in key else None)
            entry.grid(row=i, column=1, padx=5, pady=5)
            # Set the current value if it exists
            if key in self.api_keys:
                entry.insert(0, self.api_keys[key])
            self.popup_api_entries[key] = entry

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Add a save button
        save_button = tk.Button(self.api_window, text="Save", command=self.save_api_keys)
        save_button.pack(pady=10)

    def save_api_keys(self):
        # Save the API keys from the pop-up entries to self.api_keys
        for key, entry in self.popup_api_entries.items():
            self.api_keys[key] = entry.get()
        messagebox.showinfo("Info", "API keys saved successfully!")
        self.api_window.destroy()

    def setup_generate_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Generate Report")

        # Button container
        button_frame = ttk.Frame(frame)
        button_frame.pack(pady=5)

        # Green "Generate" button
        generate_btn = tk.Button(button_frame, text="Generate Report", bg="#4CAF50", fg="white",
                             command=self.generate_report_to_text)
        generate_btn.pack(side='left', padx=10)

        # Blue "Copy" button
        copy_btn = tk.Button(button_frame, text="Copy to Clipboard", bg="#2196F3", fg="white",
                         command=self.copy_report_to_clipboard)
        copy_btn.pack(side='left', padx=10)

        # Red "Clear" button
        clear_btn = tk.Button(button_frame, text="Clear", bg="#F44336", fg="white",
                          command=self.clear_report_output)
        clear_btn.pack(side='left', padx=10)

        # Text area
        self.report_output = scrolledtext.ScrolledText(frame, height=30, width=120)
        self.report_output.pack(fill='both', expand=True, padx=10, pady=5)

    def setup_triage_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Triage")

        # Label and Triage Notes Text Area
        ttk.Label(frame, text="Triage Notes:").pack(anchor='w', padx=5, pady=(5, 2))
        self.triage_text = scrolledtext.ScrolledText(frame, height=8, width=80)
        self.triage_text.insert("1.0", "Leave it blank if there are no duplicates.")
        self.triage_text.pack(fill='x', expand=False, padx=5, pady=(0, 10))

        # Duplicate Event IDs Section
        event_frame = ttk.LabelFrame(frame, text="Duplicate Event IDs")
        event_frame.pack(fill='x', padx=5, pady=0)

        # Buttons
        button_frame = ttk.Frame(event_frame)
        button_frame.grid(row=0, column=0, columnspan=2, sticky='w', padx=5, pady=5)
        tk.Button(button_frame, text="Add Event ID", bg="#4CAF50", fg="white", command=self.add_event_id).pack(side='left', padx=5)
        tk.Button(button_frame, text="Remove Event ID", bg="#F44336", fg="white", command=self.remove_event_id).pack(side='left', padx=5)

        # Container for dynamic Event ID fields
        self.event_id_container = ttk.Frame(event_frame)
        self.event_id_container.grid(row=1, column=0, columnspan=2, sticky='w', padx=5, pady=(0, 5))

        self.event_ids = []
    
    def setup_entities_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Entities")
        
        # Create scrollable frame
        canvas = tk.Canvas(frame)
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Users section
        users_frame = ttk.LabelFrame(scrollable_frame, text="Users")
        users_frame.pack(fill='x', padx=5, pady=5)
        
        users_button_frame = ttk.Frame(users_frame)
        users_button_frame.pack(fill='x', padx=5, pady=5)
        
        tk.Button(users_button_frame, text="Add User", bg="#4CAF50", fg="white", command=self.add_user).pack(side='left', padx=5)
        tk.Button(users_button_frame, text="Remove User", bg="#F44336", fg="white", command=self.remove_user).pack(side='left', padx=5)
        
        self.users_frame = ttk.Frame(users_frame)
        self.users_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Hosts section
        hosts_frame = ttk.LabelFrame(scrollable_frame, text="Hosts")
        hosts_frame.pack(fill='x', padx=5, pady=5)
        
        hosts_button_frame = ttk.Frame(hosts_frame)
        hosts_button_frame.pack(fill='x', padx=5, pady=5)
        
        tk.Button(hosts_button_frame, text="Add Host", bg="#4CAF50", fg="white", command=self.add_host).pack(side='left', padx=5)
        tk.Button(hosts_button_frame, text="Remove Host", bg="#F44336", fg="white", command=self.remove_host).pack(side='left', padx=5)
        
        self.hosts_frame = ttk.Frame(hosts_frame)
        self.hosts_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
    
    def setup_tanium_tab(self):
        # Create the tab frame
        tab_frame = ttk.Frame(self.notebook)
        self.notebook.add(tab_frame, text="Tanium Investigations")

        # Create the canvas and scrollbar
        canvas = tk.Canvas(tab_frame)
        scrollbar = ttk.Scrollbar(tab_frame, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)

        # Create the scrollable inner frame
        scrollable_frame = ttk.Frame(canvas)
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )

        # Attach the scrollable frame to the canvas
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")

        # Pack canvas and scrollbar
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Save this frame to add dynamic content later
        self.tanium_frame = scrollable_frame

        # Button bar (above investigations)
        button_frame = ttk.Frame(self.tanium_frame)
        button_frame.pack(fill='x', padx=5, pady=5)

        tk.Button(button_frame, text="Add Investigation", bg="#4CAF50", fg="white", command=self.add_tanium_investigation).pack(side='left', padx=5)
        tk.Button(button_frame, text="Remove Investigation", bg="#F44336", fg="white", command=self.remove_tanium_investigation).pack(side='left', padx=5)

    def setup_mde_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="MDE Investigations")

        button_frame = ttk.Frame(frame)
        button_frame.pack(fill='x', padx=5, pady=5)

        tk.Button(button_frame, text="Add Investigation", bg="#4CAF50", fg="white", command=self.add_mde_investigation).pack(side='left', padx=5)
        tk.Button(button_frame, text="Remove Investigation", bg="#F44336", fg="white", command=self.remove_mde_investigation).pack(side='left', padx=5)

        # Scrollable canvas
        canvas = tk.Canvas(frame)
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.mde_frame = scrollable_frame
    
    def setup_c2_domain_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="C2/Bad Rep Domain")
        
        # Create scrollable frame
        canvas = tk.Canvas(frame)
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Investigation details
        details_frame = ttk.LabelFrame(scrollable_frame, text="Investigation Details")
        details_frame.pack(fill='x', padx=5, pady=5)
        tk.Button(details_frame, text="Check Reputation", bg="#2196F3", fg="white", command=self.check_reputation).grid(row=2, column=0, columnspan=2, pady=10)
        
        ttk.Label(details_frame, text="Count:").grid(row=0, column=0, sticky='w', padx=5, pady=2)
        self.c2_count = ttk.Entry(details_frame, width=30)
        self.c2_count.grid(row=0, column=1, padx=5, pady=2)
        
        ttk.Label(details_frame, text="User Identity:").grid(row=1, column=0, sticky='w', padx=5, pady=2)
        self.c2_user_identity = ttk.Entry(details_frame, width=30)
        self.c2_user_identity.grid(row=1, column=1, padx=5, pady=2)
        
        # Destination domains
        domains_frame = ttk.LabelFrame(scrollable_frame, text="Destination Domains")
        domains_frame.pack(fill='x', padx=5, pady=5)
        
        domains_button_frame = ttk.Frame(domains_frame)
        domains_button_frame.pack(fill='x', padx=5, pady=5)
        
        tk.Button(domains_button_frame, text="Add Domain", bg="#4CAF50", fg="white", command=self.add_c2_domain).pack(side='left', padx=5)
        tk.Button(domains_button_frame, text="Remove Domain", bg="#F44336", fg="white", command=self.remove_c2_domain).pack(side='left', padx=5)
        
        self.c2_domains_frame = ttk.Frame(domains_frame)
        self.c2_domains_frame.pack(fill='both', expand=True, padx=5, pady=5)
        self.c2_domains = []
        
        # Destination IPs
        ips_frame = ttk.LabelFrame(scrollable_frame, text="Destination IPs")
        ips_frame.pack(fill='x', padx=5, pady=5)
        
        ips_button_frame = ttk.Frame(ips_frame)
        ips_button_frame.pack(fill='x', padx=5, pady=5)
        
        tk.Button(ips_button_frame, text="Add IP", bg="#4CAF50", fg="white", command=self.add_c2_ip).pack(side='left', padx=5)
        tk.Button(ips_button_frame, text="Remove IP", bg="#F44336", fg="white", command=self.remove_c2_ip).pack(side='left', padx=5)
        
        self.c2_ips_frame = ttk.Frame(ips_frame)
        self.c2_ips_frame.pack(fill='both', expand=True, padx=5, pady=5)
        self.c2_ips = []
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
    
    def setup_phishing_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Phishing")
        
        # Create scrollable frame
        canvas = tk.Canvas(frame)
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Email details
        email_frame = ttk.LabelFrame(scrollable_frame, text="Email Details")
        email_frame.pack(fill='x', padx=5, pady=5)
        
        fields = [
            ("Date:", "email_date"),
            ("Sender Address:", "sender_address"), 
            ("Sender Display Name:", "sender_display"),
            ("Return Path:", "return_path"),
            ("Reply-To:", "reply_to"),
            ("Recipients:", "recipients"),
        ]
        
        self.email_fields = {}
        for i, (label_text, field_key) in enumerate(fields):
            ttk.Label(email_frame, text=label_text).grid(row=i, column=0, sticky='w', padx=5, pady=2)
            entry = ttk.Entry(email_frame, width=50)
            entry.grid(row=i, column=1, padx=5, pady=2)
            self.email_fields[field_key] = entry
        
        auth_frame = ttk.LabelFrame(scrollable_frame, text="Authentication Protocols")
        auth_frame.pack(fill='x', padx=5, pady=5)

        ttk.Label(auth_frame, text="SPF:").grid(row=0, column=0, padx=5, pady=2)
        self.spf_result = ttk.Combobox(auth_frame, values=["Pass", "Fail", "Neutral", "Softfail", "None"], width=15)
        self.spf_result.grid(row=0, column=1, padx=5, pady=2)

        ttk.Label(auth_frame, text="DKIM:").grid(row=0, column=2, padx=5, pady=2)
        self.dkim_result = ttk.Combobox(auth_frame, values=["Pass", "Fail", "Neutral", "None"], width=15)
        self.dkim_result.grid(row=0, column=3, padx=5, pady=2)

        ttk.Label(auth_frame, text="DMARC:").grid(row=0, column=4, padx=5, pady=2)
        self.dmarc_result = ttk.Combobox(auth_frame, values=["Pass", "Fail", "None"], width=15)
        self.dmarc_result.grid(row=0, column=5, padx=5, pady=2)


        ttk.Label(email_frame, text="Threat Label:").grid(row=6, column=0, sticky='w', padx=5, pady=2)
        self.threat_label = ttk.Combobox(email_frame, values=["None", "Spam", "Phish"], width=47)
        self.threat_label.grid(row=6, column=1, padx=5, pady=2)

        ttk.Label(email_frame, text="Original Delivery Location:").grid(row=7, column=0, sticky='w', padx=5, pady=2)
        self.original_delivery = ttk.Combobox(email_frame, values=["Dropped", "Failed", "Inbox/folder", "Junk folder", "On-prem/external", "Quarantine", "Unknown"], width=47)
        self.original_delivery.grid(row=7, column=1, padx=5, pady=2)

        ttk.Label(email_frame, text="Latest Delivery Location:").grid(row=8, column=0, sticky='w', padx=5, pady=2)
        self.latest_delivery = ttk.Combobox(email_frame, values=["Dropped", "Failed", "Inbox/folder", "Junk folder", "On-prem/external", "Quarantine", "Unknown"], width=47)
        self.latest_delivery.grid(row=8, column=1, padx=5, pady=2)

        # IP Analysis section
        ip_frame = ttk.LabelFrame(scrollable_frame, text="IP Analysis")
        ip_frame.pack(fill='x', padx=5, pady=5)
        
        ip_button_frame = ttk.Frame(ip_frame)
        ip_button_frame.pack(fill='x', padx=5, pady=5)
        
        tk.Button(ip_button_frame, text="Add IP", bg="#4CAF50", fg="white", command=self.add_phishing_ip).pack(side='left', padx=5)
        tk.Button(ip_button_frame, text="Remove IP", bg="#F44336", fg="white", command=self.remove_phishing_ip).pack(side='left', padx=5)
        tk.Button(ip_button_frame, text="Check IPs", bg="#2196F3", fg="white", command=self.check_phishing_ips).pack(side='left', padx=5)

        self.phishing_ips_frame = ttk.Frame(ip_frame)
        self.phishing_ips_frame.pack(fill='both', expand=True, padx=5, pady=5)
        self.phishing_ips = []
        
        # Links section
        links_frame = ttk.LabelFrame(scrollable_frame, text="Links")
        links_frame.pack(fill='x', padx=5, pady=5)
        
        links_button_frame = ttk.Frame(links_frame)
        links_button_frame.pack(fill='x', padx=5, pady=5)
        
        tk.Button(links_button_frame, text="Add Link", bg="#4CAF50", fg="white", command=self.add_phishing_link).pack(side='left', padx=5)
        tk.Button(links_button_frame, text="Remove Link", bg="#F44336", fg="white", command=self.remove_phishing_link).pack(side='left', padx=5)
        tk.Button(links_button_frame, text="Check URLs", bg="#2196F3", fg="white", command=self.check_phishing_urls).pack(side='left', padx=5)
        
        self.phishing_links_frame = ttk.Frame(links_frame)
        self.phishing_links_frame.pack(fill='both', expand=True, padx=5, pady=5)
        self.phishing_links = []
        
        # Attachments section
        attach_frame = ttk.LabelFrame(scrollable_frame, text="Attachments")
        attach_frame.pack(fill='x', padx=5, pady=5)
        
        attach_button_frame = ttk.Frame(attach_frame)
        attach_button_frame.pack(fill='x', padx=5, pady=5)
        
        tk.Button(attach_button_frame, text="Add Attachment", bg="#4CAF50", fg="white", command=self.add_attachment).pack(side='left', padx=5)
        tk.Button(attach_button_frame, text="Remove Attachment", bg="#F44336", fg="white", command=self.remove_attachment).pack(side='left', padx=5)
        tk.Button(attach_button_frame, text="Check Hashes", bg="#2196F3", fg="white", command=self.check_phishing_hashes).pack(side='left', padx=5)

        self.attachments_frame = ttk.Frame(attach_frame)
        self.attachments_frame.pack(fill='both', expand=True, padx=5, pady=5)
        self.attachments = []
        
        # Additional Information
        additional_frame = ttk.LabelFrame(scrollable_frame, text="Additional Information")
        additional_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.additional_info = scrolledtext.ScrolledText(additional_frame, height=8)
        self.additional_info.pack(fill='both', expand=True, padx=5, pady=5)
        
        chain_frame = ttk.LabelFrame(scrollable_frame, text="Email Chain")
        chain_frame.pack(fill='both', expand=True, padx=5, pady=5)

        self.email_chain_input = scrolledtext.ScrolledText(chain_frame, height=10)
        self.email_chain_input.pack(fill='both', expand=True, padx=5, pady=5)

        tk.Button(chain_frame, text="Format Email Chain", bg="#2196F3", fg="white", command=self.format_email_chain).pack(pady=5)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
    
    def setup_queries_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Queries")
        
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill='x', padx=5, pady=5)
        
        tk.Button(button_frame, text="Add Query", bg="#4CAF50", fg="white", command=self.add_query).pack(side='left', padx=5)
        tk.Button(button_frame, text="Remove Query", bg="#F44336", fg="white", command=self.remove_query).pack(side='left', padx=5)
        
        self.queries_frame = ttk.Frame(frame)
        self.queries_frame.pack(fill='both', expand=True, padx=5, pady=5)

    def setup_vmlab_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="VM Lab")

        # Scrollable canvas
        canvas = tk.Canvas(frame)
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # FILE REVIEW
        file_frame = ttk.LabelFrame(scrollable_frame, text="File Review")
        file_frame.pack(fill='x', padx=5, pady=5)

        file_button_frame = ttk.Frame(file_frame)
        file_button_frame.pack(anchor='w', padx=5, pady=5)

        tk.Button(file_button_frame, text="Add File", bg="#4CAF50", fg="white", command=self.add_file_review).pack(side='left', padx=5)
        tk.Button(file_button_frame, text="Remove File", bg="#F44336", fg="white", command=self.remove_file_review).pack(side='left', padx=5)

        self.file_review_container = ttk.Frame(file_frame)
        self.file_review_container.pack(fill='x', padx=5, pady=5)

        self.file_reviews = []

        # URL Review
        url_frame = ttk.LabelFrame(scrollable_frame, text="URL Review")
        url_frame.pack(fill='x', padx=5, pady=5)

        url_button_frame = ttk.Frame(url_frame)
        url_button_frame.pack(anchor='w', padx=5, pady=5)

        tk.Button(url_button_frame, text="Add URL", bg="#4CAF50", fg="white", command=self.add_url_review).pack(side='left', padx=5)
        tk.Button(url_button_frame, text="Remove URL", bg="#F44336", fg="white", command=self.remove_url_review).pack(side='left', padx=5)

        self.url_review_container = ttk.Frame(url_frame)
        self.url_review_container.pack(fill='x', padx=5, pady=5)

        self.url_reviews = []
    
    def setup_conclusion_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Conclusion")
        
        ttk.Label(frame, text="Investigation Conclusion:").pack(anchor='w', padx=5, pady=5)
        self.conclusion_text = scrolledtext.ScrolledText(frame, height=20, width=80)
        self.conclusion_text.pack(fill='both', expand=True, padx=5, pady=5)

    # Generate report
    def generate_report_to_text(self):
        report = self.compile_report()
        self.report_output.delete("1.0", tk.END)
        self.report_output.insert("1.0", report)
    
    # Clipboard functions
    def copy_report_to_clipboard(self):
        text = self.report_output.get("1.0", tk.END)
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.root.update() 

    def clear_report_output(self):
        self.report_output.delete("1.0", tk.END)

    # Event_Id functions
    def add_event_id(self):
        row = len(self.event_ids)
        frame = ttk.Frame(self.event_id_container)
        frame.pack(fill='x', pady=2)

        ttk.Label(frame, text=f"Event ID {row + 1}:").pack(side='left', padx=5)
        entry = ttk.Entry(frame, width=40)
        entry.pack(side='left', padx=5)

        self.event_ids.append({
        'frame': frame,
        'entry': entry
        })

    def remove_event_id(self):
        if self.event_ids:
            last = self.event_ids.pop()
            last['frame'].destroy()

    # Entity management methods
    def add_user(self):
        row = len(self.entities['users'])
        user_frame = ttk.LabelFrame(self.users_frame, text=f"User {row+1}")
        user_frame.pack(fill='x', padx=5, pady=2)
        
        fields = [
            ("User:", "username"),
            ("Job Title:", "job_title"),
            ("Company:", "company"),
            ("Entra ID Sign-in Logs:", "signin_logs"),
            ("Entra ID Audit Logs:", "audit_logs")
        ]
        
        user_entries = {}
        for i, (label_text, field_key) in enumerate(fields):
            ttk.Label(user_frame, text=label_text).grid(row=i, column=0, sticky='w', padx=5, pady=2)
            entry = ttk.Entry(user_frame, width=40)
            entry.grid(row=i, column=1, padx=5, pady=2)
            user_entries[field_key] = entry
        
        self.entities['users'].append({
            'frame': user_frame,
            'entries': user_entries
        })
    
    def remove_user(self):
        if self.entities['users']:
            user = self.entities['users'].pop()
            user['frame'].destroy()
    
    def add_host(self):
        row = len(self.entities['hosts'])
        host_frame = ttk.LabelFrame(self.hosts_frame, text=f"Host {row+1}")
        host_frame.pack(fill='x', padx=5, pady=2)
        
        fields = [
            ("Hostname:", "hostname"),
            ("Local IP Address:", "local_ip"),
            ("OS:", "os")
        ]
        
        host_entries = {}
        for i, (label_text, field_key) in enumerate(fields):
            ttk.Label(host_frame, text=label_text).grid(row=i, column=0, sticky='w', padx=5, pady=2)
            entry = ttk.Entry(host_frame, width=40)
            entry.grid(row=i, column=1, padx=5, pady=2)
            host_entries[field_key] = entry
        
        self.entities['hosts'].append({
            'frame': host_frame,
            'entries': host_entries
        })
    
    def remove_host(self):
        if self.entities['hosts']:
            host = self.entities['hosts'].pop()
            host['frame'].destroy()
    
    # Phishing management methods
    def add_phishing_ip(self):
        row = len(self.phishing_ips)
        ip_frame = ttk.LabelFrame(self.phishing_ips_frame, text=f"IP {row+1}")
        ip_frame.pack(fill='x', padx=5, pady=2)
        
        ttk.Label(ip_frame, text="IP Address:").grid(row=0, column=0, sticky='w', padx=5, pady=2)
        ip_entry = ttk.Entry(ip_frame, width=30)
        ip_entry.grid(row=0, column=1, padx=5, pady=2)
        
        ttk.Label(ip_frame, text="Type:").grid(row=1, column=0, sticky='w', padx=5, pady=2)
        type_combo = ttk.Combobox(ip_frame, values=["Sender IP", "First Hop"], width=27)
        type_combo.grid(row=1, column=1, padx=5, pady=2)
        
        ttk.Label(ip_frame, text="Analysis Results:").grid(row=2, column=0, sticky='w', padx=5, pady=2)
        results_text = scrolledtext.ScrolledText(ip_frame, height=4, width=50)
        results_text.grid(row=2, column=1, padx=5, pady=2)
        
        self.phishing_ips.append({
            'frame': ip_frame,
            'ip': ip_entry,
            'type': type_combo,
            'results': results_text
        })
    
    def remove_phishing_ip(self):
        if self.phishing_ips:
            ip = self.phishing_ips.pop()
            ip['frame'].destroy()
    
    def add_phishing_link(self):
        row = len(self.phishing_links)
        link_frame = ttk.LabelFrame(self.phishing_links_frame, text=f"Link {row+1}")
        link_frame.pack(fill='x', padx=5, pady=2)
        
        ttk.Label(link_frame, text="URL:").grid(row=0, column=0, sticky='w', padx=5, pady=2)
        url_entry = ttk.Entry(link_frame, width=50)
        url_entry.grid(row=0, column=1, padx=5, pady=2)
        
        ttk.Label(link_frame, text="Analysis Results:").grid(row=1, column=0, sticky='w', padx=5, pady=2)
        results_entry = ttk.Entry(link_frame, width=50)
        results_entry.grid(row=1, column=1, padx=5, pady=2)
        
        self.phishing_links.append({
            'frame': link_frame,
            'url': url_entry,
            'results': results_entry
        })
    
    def remove_phishing_link(self):
        if self.phishing_links:
            link = self.phishing_links.pop()
            link['frame'].destroy()
    
    def add_attachment(self):
        row = len(self.attachments)
        attach_frame = ttk.LabelFrame(self.attachments_frame, text=f"Attachment {row+1}")
        attach_frame.pack(fill='x', padx=5, pady=2)
        
        ttk.Label(attach_frame, text="Filename:").grid(row=0, column=0, sticky='w', padx=5, pady=2)
        filename_entry = ttk.Entry(attach_frame, width=30)
        filename_entry.grid(row=0, column=1, padx=5, pady=2)
        
        ttk.Label(attach_frame, text="SHA256:").grid(row=1, column=0, sticky='w', padx=5, pady=2)
        hash_entry = ttk.Entry(attach_frame, width=50)
        hash_entry.grid(row=1, column=1, padx=5, pady=2)
        
        ttk.Label(attach_frame, text="Analysis Results:").grid(row=2, column=0, sticky='w', padx=5, pady=2)
        results_entry = ttk.Entry(attach_frame, width=50)
        results_entry.grid(row=2, column=1, padx=5, pady=2)
        
        self.attachments.append({
            'frame': attach_frame,
            'filename': filename_entry,
            'hash': hash_entry,
            'results': results_entry
        })
    
    def remove_attachment(self):
        if self.attachments:
            attachment = self.attachments.pop()
            attachment['frame'].destroy()
    
    # C2 management methods
    def add_c2_domain(self):
        row = len(self.c2_domains)
        domain_frame = ttk.LabelFrame(self.c2_domains_frame, text=f"Domain {row+1}")
        domain_frame.pack(fill='x', padx=5, pady=2)
        
        ttk.Label(domain_frame, text="Domain:").grid(row=0, column=0, sticky='w', padx=5, pady=2)
        domain_entry = ttk.Entry(domain_frame, width=40)
        domain_entry.grid(row=0, column=1, padx=5, pady=2)
        
        ttk.Label(domain_frame, text="Analysis Results:").grid(row=1, column=0, sticky='w', padx=5, pady=2)
        results_entry = ttk.Entry(domain_frame, width=50)
        results_entry.grid(row=1, column=1, padx=5, pady=2)
        
        self.c2_domains.append({
            'frame': domain_frame,
            'domain': domain_entry,
            'results': results_entry
        })
    
    def remove_c2_domain(self):
        if self.c2_domains:
            domain = self.c2_domains.pop()
            domain['frame'].destroy()
    
    def add_c2_ip(self):
        row = len(self.c2_ips)
        ip_frame = ttk.LabelFrame(self.c2_ips_frame, text=f"IP {row+1}")
        ip_frame.pack(fill='x', padx=5, pady=2)
        
        ttk.Label(ip_frame, text="IP Address:").grid(row=0, column=0, sticky='w', padx=5, pady=2)
        ip_entry = ttk.Entry(ip_frame, width=30)
        ip_entry.grid(row=0, column=1, padx=5, pady=2)
        
        ttk.Label(ip_frame, text="Analysis Results:").grid(row=1, column=0, sticky='w', padx=5, pady=2)
        results_text = scrolledtext.ScrolledText(ip_frame, height=3, width=50)
        results_text.grid(row=1, column=1, padx=5, pady=2)
        
        self.c2_ips.append({
            'frame': ip_frame,
            'ip': ip_entry,
            'results': results_text
        })
    
    def remove_c2_ip(self):
        if self.c2_ips:
            ip = self.c2_ips.pop()
            ip['frame'].destroy()

    def add_tanium_investigation(self):
        # Create a container for the whole investigation
        container = ttk.LabelFrame(self.tanium_frame, text="Intel Investigation", padding=10)
        container.pack(fill='x', padx=10, pady=10)

        # Intel input
        ttk.Label(container, text="Intel Event:").grid(row=0, column=0, sticky='w')
        intel_entry = ttk.Entry(container, width=60)
        intel_entry.grid(row=0, column=1, pady=5, sticky='w')

        # Host container (inside this investigation)
        host_container = ttk.Frame(container)
        host_container.grid(row=1, column=0, columnspan=2, sticky='nsew')

        # Track this investigation
        intel_data = {
            'frame': container,
            'intel': intel_entry,
            'hosts': [],
            'host_container': host_container  
        }
        self.tanium_investigations.append(intel_data)

        # Buttons to add/remove hosts
        button_frame = ttk.Frame(container)
        button_frame.grid(row=2, column=0, columnspan=2, pady=5)

        tk.Button(button_frame, text="Add Host", bg="#4CAF50", fg="white", command=lambda: self.add_tanium_host_block(host_container, intel_data)).pack(side='left', padx=5)
        tk.Button(button_frame, text="Remove Host", bg="#F44336", fg="white", command=lambda: self.remove_tanium_host_block(intel_data)).pack(side='left', padx=5)

        def toggle_frame(frame, btn):
            if frame.winfo_ismapped():
                frame.grid_remove()
                btn.config(text="Expand")
            else:
                frame.grid()
                btn.config(text="Collapse")

        toggle_btn = tk.Button(container, text="Collapse", command=lambda: toggle_frame(host_container, toggle_btn))
        toggle_btn.grid(row=3, column=0, columnspan=2)

        # Add first host block by default
        self.add_tanium_host_block(host_container, intel_data)

    def remove_tanium_investigation(self):
        if self.tanium_investigations:
            inv = self.tanium_investigations.pop()
            inv['frame'].destroy()
    
    def add_tanium_host_block(self, container, intel_data):
        host_frame = ttk.LabelFrame(container, text="Host Investigation", padding=10)
        host_frame.pack(fill='x', padx=10, pady=10)

        def add_row(label, row, width=40):
            ttk.Label(host_frame, text=label).grid(row=row, column=0, sticky='w')
            entry = ttk.Entry(host_frame, width=width)
            entry.grid(row=row, column=1, sticky='w')
            return entry

        hostname = add_row("Hostname:", 0, width=40)
        action = add_row("Action Taken:", 1, width=40)
        ttk.Label(host_frame, text="Command:").grid(row=2, column=0, sticky='nw')
        command_text = scrolledtext.ScrolledText(host_frame, height=3, width=60)
        command_text.grid(row=2, column=1, columnspan=2, pady=3)
        timestamp = add_row("Timestamp:", 3, width=40)
        child_proc = add_row("Child Process:", 4, width=70)
        child_hash = add_row("Child SHA256:", 5, width=70)
        child_result_label = tk.StringVar()
        parent_proc = add_row("Parent Process:", 7, width=70)
        parent_hash = add_row("Parent SHA256:", 8, width=70)
        parent_result_label = tk.StringVar()

        def check_child():
            vt_key = self.api_keys.get('virustotal', '')
            hash_val = child_hash.get().strip()
            if hash_val:
                result = self.vt_hash_lookup(hash_val, vt_key)
                child_result_label.set(result)
                host_dict['child_reputation'] = result

        def check_parent():
            vt_key = self.api_keys.get('virustotal', '')
            hash_val = parent_hash.get().strip()
            if hash_val:
                result = self.vt_hash_lookup(hash_val, vt_key)
                parent_result_label.set(result)
                host_dict['parent_reputation'] = result

        tk.Button(host_frame, text="Check Child Hash", bg="#2196F3", fg="white", command=check_child).grid(row=6, column=0, padx=5)
        tk.Button(host_frame, text="Check Parent Hash", bg="#2196F3", fg="white", command=check_parent).grid(row=9, column=0, padx=5)

        ttk.Label(host_frame, textvariable=child_result_label, wraplength=300, foreground="blue").grid(row=6, column=1, padx=5)
        ttk.Label(host_frame, textvariable=parent_result_label, wraplength=300, foreground="blue").grid(row=9, column=1, padx=5)

        # Process Tree
        ttk.Label(host_frame, text="Process Tree:").grid(row=10, column=0, sticky='nw')
        tree_text = scrolledtext.ScrolledText(host_frame, height=6, width=60)
        tree_text.grid(row=10, column=1, columnspan=2, pady=3)

        def format_tree():
            raw = tree_text.get("1.0", tk.END).strip().replace('\r\n', '\n').split('\n')
            if len(raw) % 4 != 0:
                messagebox.showerror("Invalid Format", f"Expected multiples of 4 lines, got {len(raw)}")
                return
            chunks = [raw[i:i+4] for i in range(0, len(raw), 4)][::-1]
            formatted = ""
            for i, (name, user, pid, full_cmd) in enumerate(chunks):
                indent = " " * i
                arrow = "↳ " if i > 0 else ""
                formatted += f"{indent}{arrow}{full_cmd} ({user}, PID:{pid})\n"
            tree_text.delete("1.0", tk.END)
            tree_text.insert("1.0", formatted.strip())

        ttk.Button(host_frame, text="Format Tree", command=format_tree).grid(row=11, column=2, pady=3)

        # Other fields (file activity, registry changes, etc.)
        def add_textarea(label, row):
            ttk.Label(host_frame, text=label).grid(row=row, column=0, sticky='nw')
            area = scrolledtext.ScrolledText(host_frame, height=3, width=60)
            area.grid(row=row, column=1, columnspan=3, pady=3)
            return area

        file_activity = add_textarea("File Activity:", 12)
        reg_changes = add_textarea("Registry Changes:", 13)
        net_activity = add_textarea("Network Activity:", 14)
        dns_calls = add_textarea("DNS Calls:", 15)
        additional_info = add_textarea("Additional Info:", 16)

        host_dict = {
            'frame': host_frame,
        'hostname': hostname,
        'action': action,
        'command': command_text,
        'timestamp': timestamp,
        'child_proc': child_proc,
        'child_hash': child_hash,
        'child_reputation': '',
        'parent_proc': parent_proc,
        'parent_hash': parent_hash,
        'parent_reputation': '',
        'tree': tree_text,
        'file_activity': file_activity,
        'reg_changes': reg_changes,
        'net_activity': net_activity,
        'dns_calls': dns_calls,
        'additional_info': additional_info
        }
        intel_data['hosts'].append(host_dict)

    def remove_tanium_host_block(self, intel_data):
        if intel_data['hosts']:
            host = intel_data['hosts'].pop()
            host['frame'].destroy()
    
    def add_mde_investigation(self):
        inv_frame = ttk.LabelFrame(self.mde_frame, text="MDE Investigation", padding=10)
        inv_frame.pack(fill='x', padx=10, pady=5, anchor='n')

        # Collapse/Expand toggle
        toggle_btn = ttk.Button(inv_frame, text="Collapse", width=10)
        toggle_btn.pack(anchor='ne')

        content_frame = ttk.Frame(inv_frame)
        content_frame.pack(fill='x', pady=5)

        ttk.Label(content_frame, text="Signature:").grid(row=0, column=0, sticky='w')
        signature_entry = ttk.Entry(content_frame, width=60)
        signature_entry.grid(row=0, column=1, sticky='w')

        links_frame = ttk.Frame(content_frame)
        links_frame.grid(row=1, column=0, columnspan=2, pady=5, sticky='w')

        links = []

        def add_link_row():
            row = len(links)
    
            # Add labels only for the first row
            if row == 0:
                ttk.Label(links_frame, text="Link:").grid(row=0, column=0, sticky='w')
                ttk.Label(links_frame, text="Result:").grid(row=0, column=1, sticky='w')

            link_entry = scrolledtext.ScrolledText(links_frame, width=50, height=3)
            result_box = scrolledtext.ScrolledText(links_frame, width=50, height=3)

            link_entry.grid(row=row * 2 + 1, column=0, padx=2, pady=2, sticky='w')
            result_box.grid(row=row * 2 + 1, column=1, padx=2, pady=2, sticky='w')

            links.append({'link': link_entry, 'result': result_box})

        def remove_last_link():
            if links:
                last = links.pop()
                last['link'].destroy()
                last['result'].destroy()

        add_link_btn = tk.Button(content_frame, text="Add Link", bg="#4CAF50", fg="white", command=add_link_row)
        rem_link_btn = tk.Button(content_frame, text="Remove Link", bg="#F44336", fg="white", command=remove_last_link)
        add_link_btn.grid(row=2, column=0, sticky='w', pady=3)
        rem_link_btn.grid(row=2, column=1, sticky='w', pady=3)

        def toggle():
            if content_frame.winfo_ismapped():
                content_frame.pack_forget()
                toggle_btn.config(text="Expand")
            else:
                content_frame.pack(fill='x', pady=5)
                toggle_btn.config(text="Collapse")

        toggle_btn.config(command=toggle)

        # Add one link row by default
        add_link_row()

        self.mde_investigations.append({
            'frame': inv_frame,
            'signature': signature_entry,
            'links': links
        })

    def remove_mde_investigation(self):
        if self.mde_investigations:
            last = self.mde_investigations.pop()
            last['frame'].destroy()
    
    # Domain/IP management
    def add_domain_ip(self):
        row = len(self.domains_ips)
        domain_frame = ttk.Frame(self.domains_frame)
        domain_frame.pack(fill='x', padx=5, pady=2)
        
        ttk.Label(domain_frame, text=f"Domain/IP {row+1}:").pack(side='left', padx=5)
        domain_entry = ttk.Entry(domain_frame, width=30)
        domain_entry.pack(side='left', padx=5)
        
        ttk.Label(domain_frame, text="Reputation:").pack(side='left', padx=5)
        reputation_entry = ttk.Entry(domain_frame, width=50)
        reputation_entry.pack(side='left', padx=5)
        
        self.domains_ips.append({
            'frame': domain_frame,
            'domain': domain_entry,
            'reputation': reputation_entry
        })
    
    def remove_domain_ip(self):
        if self.domains_ips:
            domain = self.domains_ips.pop()
            domain['frame'].destroy()
    
    # Query management
    def add_query(self):
        row = len(self.queries)
        query_frame = ttk.LabelFrame(self.queries_frame, text=f"Query {row+1}")
        query_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(query_frame, text="Type:").grid(row=0, column=0, sticky='w', padx=5, pady=2)
        type_combo = ttk.Combobox(query_frame, values=["SPL", "KQL", "Tanium"], width=20)
        type_combo.grid(row=0, column=1, padx=5, pady=2)
        
        ttk.Label(query_frame, text="Query:").grid(row=1, column=0, sticky='w', padx=5, pady=2)
        query_text = scrolledtext.ScrolledText(query_frame, height=3, width=60)
        query_text.grid(row=1, column=1, padx=5, pady=2)
        
        ttk.Label(query_frame, text="Results:").grid(row=2, column=0, sticky='w', padx=5, pady=2)
        results_text = scrolledtext.ScrolledText(query_frame, height=5, width=60)
        results_text.grid(row=2, column=1, padx=5, pady=2)
        
        self.queries.append({
            'frame': query_frame,
            'type': type_combo,
            'query': query_text,
            'results': results_text
        })
    
    def remove_query(self):
        if self.queries:
            query = self.queries.pop()
            query['frame'].destroy()
    
    # API integration methods
    def check_reputation(self):
        vt_key = self.api_keys.get('virustotal', '')
        abuse_key = self.api_keys.get('abuseipdb', '')

        if not vt_key and not abuse_key:
            messagebox.showwarning("Warning", "No API keys configured for reputation check")
            return

        for domain_info in self.c2_domains:
            domain = domain_info['domain'].get()
            if domain:
                rep = self.get_reputation(domain, vt_key, abuse_key)
                domain_info['results'].delete(0, tk.END)
                domain_info['results'].insert(0, rep)

        for ip_info in self.c2_ips:
            ip = ip_info['ip'].get()
            if ip:
                rep = self.get_reputation(ip, vt_key, abuse_key)
                ip_info['results'].delete("1.0", tk.END)
                ip_info['results'].insert("1.0", rep)
    
    def get_reputation(self, ip_or_domain, vt_key, abuse_key):
        lines = []

        # VT
        if vt_key:
            vt = self.vt_ip_or_domain_lookup(ip_or_domain, vt_key)
            lines.append(f"{vt}")

        # AbuseIPDB
        if abuse_key and self.is_ip(ip_or_domain):
            abuse = self.abuseipdb_lookup(ip_or_domain, abuse_key)
            lines.append(f"{abuse}")

        # Scamalytics
        scam_user = self.api_keys.get('scamalytics_username', '')
        scam_key = self.api_keys.get('scamalytics', '')
        if self.is_ip(ip_or_domain) and scam_key and scam_user:
            scam = self.scamalytics_lookup(ip_or_domain, scam_user, scam_key)
            lines.append(scam)

        return "\n".join(lines) if lines else "No reputation data"

    def vt_ip_or_domain_lookup(self, value, api_key):
        headers = {"x-apikey": api_key}

        # Decide if it's an IP or domain
        import ipaddress
        try:
            ipaddress.ip_address(value)
            is_ip = True
        except ValueError:
            is_ip = False

        url = f"https://www.virustotal.com/api/v3/{'ip_addresses' if is_ip else 'domains'}/{value}"

        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes'].get('last_analysis_stats', {})
                results = data['data']['attributes'].get('last_analysis_results', {})
                malicious = stats.get('malicious', 0)
                total = sum(stats.values())
                flagged_by = [engine for engine, result in results.items() if result['category'] == 'malicious']

                if malicious == 0:
                    return f"VT results: 0/{total} malicious detections"
                else:
                    return f"VT results: {malicious}/{total} malicious detections, flagged by: {', '.join(flagged_by)}"
            elif response.status_code == 404:
                return f"VT: Not found for {'IP' if is_ip else 'domain'} {value}"
            else:
                return f"VT Error {response.status_code}"
        except Exception as e:
            return f"VT Exception: {e}"

    def vt_url_lookup(self, url, api_key):
        import base64
        try:
            # Encode URL (no padding)
            encoded = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
            headers = {"x-apikey": api_key}
            vt_url = f"https://www.virustotal.com/api/v3/urls/{encoded}"

            response = requests.get(vt_url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes'].get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                total = sum(stats.values())
                return f"VT results: {malicious}/{total} malicious detections"
            elif response.status_code == 404:
                return "VT: Not found"
            else:
                return f"VT Error {response.status_code}"
        except Exception as e:
            return f"VT Exception: {e}"

    def vt_hash_lookup(self, file_hash, api_key):
        headers = {"x-apikey": api_key}
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes'].get('last_analysis_stats', {})
                results = data['data']['attributes'].get('last_analysis_results', {})
                malicious = stats.get('malicious', 0)
                total = sum(stats.values())
                flagged_by = [engine for engine, result in results.items() if result['category'] == 'malicious']

                if malicious == 0:
                    return f"VT results: 0/{total} malicious detections"
                else:
                    return f"VT results: {malicious}/{total} malicious detections, flagged by: {', '.join(flagged_by)}"
            elif response.status_code == 404:
                return "VT: Not found"
            else:
                return f"VT Error {response.status_code}"
        except Exception as e:
            return f"VT Exception: {e}"


    def abuseipdb_lookup(self, ip, api_key):
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": api_key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": "90"
        }
        try:
            resp = requests.get(url, headers=headers, params=params)
            if resp.status_code == 200:
                data = resp.json()['data']
                score = data.get('abuseConfidenceScore', 0)
                country = data.get('countryCode', 'N/A')
                usage = data.get('usageType', 'N/A')
                domain = data.get('domain', 'N/A')
                total = data.get('totalReports', 0)

                return f"AbuseIPDB: {score}/100 confidence score | Country: {country} | Usage: {usage} | Domain: {domain} | Total reports: {total}"
            else:
                return f"AbuseIPDB Error {resp.status_code}"
        except Exception as e:
            return f"AbuseIPDB Exception: {e}"

    def scamalytics_lookup(self, ip, scam_user, scam_key):
        url = f"https://api12.scamalytics.com/v3/{scam_user}/?key={scam_key}&ip={ip}"
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                scam = data.get("scamalytics", {})
                ext = data.get("external_datasources", {})

                score = scam.get("scamalytics_score", "N/A")
                risk = scam.get("scamalytics_risk", "N/A")

                # Country
                country = ext.get("ip2proxy_lite", {}).get("ip_country_code") \
                    or ext.get("ipinfo", {}).get("ip_country_code") or "N/A"

                # Blacklisted sources
                sources = []
                if ext.get("ipsum", {}).get("ip_blacklisted"):
                    sources.append("IPsum")
                if ext.get("spamhaus_drop", {}).get("ip_blacklisted"):
                    sources.append("Spamhaus")
                blacklist = f"Yes ({', '.join(sources)})" if sources else "No"

                # Proxy detection
                proxy_flags = []
                proxy = scam.get("scamalytics_proxy", {})
                if proxy.get("is_vpn"): proxy_flags.append("Anonymizing VPN")
                if proxy.get("is_datacenter"): proxy_flags.append("Datacenter")
                proxy_status = f"Yes - {', '.join(proxy_flags)}" if proxy_flags else "No"

                return f"Scamalytics: Score: {score} (Risk: {risk}) | Country: {country} | Blacklisted: {blacklist} | Proxies: {proxy_status}"
            else:
                return f"Scamalytics Error {resp.status_code}"
        except Exception as e:
            return f"Scamalytics Exception: {e}"

    def urlscan_lookup(self, url, api_key):
        headers = {
            "API-Key": api_key,
            "Content-Type": "application/json"
        }

        try:
            # Submit URL for scanning
            submission = requests.post("https://urlscan.io/api/v1/scan/",
                                   headers=headers,
                                   json={"url": url})
            if submission.status_code == 200:
                scan_data = submission.json()
                result_url = scan_data.get("result", "N/A")
                uuid = scan_data.get("uuid")

                # Wait for result to become available
                import time
                time.sleep(15)

                result = requests.get(f"https://urlscan.io/api/v1/result/{uuid}")
                if result.status_code == 200:
                    data = result.json()
                    verdict = data.get("verdicts", {}).get("overall", {})
                    score = verdict.get("score", "unknown")
                    return f"URLScan: Score = {score}, [View Scan]({result_url})"
                else:
                    return f"URLScan: Submitted. [View Scan]({result_url})"
            else:
                return f"URLScan: Failed to submit URL ({submission.status_code})"
        except Exception as e:
            return f"URLScan Exception: {e}"


    def check_phishing_ips(self):
        vt_key = self.api_keys.get('virustotal', '')
        abuse_key = self.api_keys.get('abuseipdb', '')
        scam_user = self.api_keys.get('scamalytics_username', '')
        scam_key = self.api_keys.get('scamalytics', '')

        if not vt_key and not abuse_key and not (scam_user and scam_key):
            messagebox.showwarning("Warning", "No API keys configured for IP analysis")
            return

        for ip_obj in self.phishing_ips:
            ip_addr = ip_obj['ip'].get()
            if not ip_addr:
                continue

            results = []

            if vt_key:
                results.append(f"{self.vt_ip_or_domain_lookup(ip_addr, vt_key)}")
            if abuse_key and self.is_ip(ip_addr):
                results.append(f"{self.abuseipdb_lookup(ip_addr, abuse_key)}")
            if scam_key and scam_user and self.is_ip(ip_addr):
                results.append(f"{self.scamalytics_lookup(ip_addr, scam_user, scam_key)}")

            ip_obj['results'].delete("1.0", tk.END)
            ip_obj['results'].insert("1.0", "\n".join(results))

    def check_phishing_urls(self):
        vt_key = self.api_keys.get('virustotal', '')
        urlscan_key = self.api_keys.get('urlscan', '')

        if not vt_key and not urlscan_key:
            messagebox.showwarning("Warning", "No API keys configured for URL analysis")
            return

        for link in self.phishing_links:
            url = link['url'].get()
            if not url:
                continue

            results = []
            if vt_key:
                results.append(self.vt_url_lookup(url, vt_key))
            if urlscan_key:
                results.append(self.urlscan_lookup(url, urlscan_key))

            # Update the results field
            if isinstance(link['results'], scrolledtext.ScrolledText):
                link['results'].delete("1.0", tk.END)
                link['results'].insert("1.0", "\n".join(results))
            else:
                link['results'].delete(0, tk.END)
                link['results'].insert(0, " | ".join(results))
    
    def check_phishing_hashes(self):
        vt_key = self.api_keys.get('virustotal', '')
        if not vt_key:
            messagebox.showwarning("Warning", "VirusTotal API key not configured")
            return

        for att in self.attachments:
            hash_value = att['hash'].get()
            if not hash_value:
                continue

            result = self.vt_hash_lookup(hash_value, vt_key)
            if isinstance(att['results'], scrolledtext.ScrolledText):
                att['results'].delete("1.0", tk.END)
                att['results'].insert("1.0", result)
            else:
                att['results'].delete(0, tk.END)
                att['results'].insert(0, result)

    # VM - FILES
    def add_file_review(self):
        frame = ttk.LabelFrame(self.file_review_container, text=f"File Review {len(self.file_reviews) + 1}")
        frame.pack(fill='x', padx=5, pady=5)

        ttk.Label(frame, text="File Investigated:").pack(anchor='w', padx=5, pady=(5, 0))
        filename_entry = ttk.Entry(frame, width=80)
        filename_entry.pack(fill='x', padx=5)

        ttk.Label(frame, text="Results:").pack(anchor='w', padx=5, pady=(5, 0))
        results_text = scrolledtext.ScrolledText(frame, height=4)
        results_text.pack(fill='x', padx=5)

        ttk.Label(frame, text="File Content:").pack(anchor='w', padx=5, pady=(5, 0))
        content_text = scrolledtext.ScrolledText(frame, height=6)
        content_text.pack(fill='x', padx=5, pady=(0, 5))

        self.file_reviews.append({
            'frame': frame,
            'filename': filename_entry,
            'results': results_text,
            'content': content_text
        })

    def remove_file_review(self):
        if self.file_reviews:
            last = self.file_reviews.pop()
            last['frame'].destroy()

    # VM - URL
    def add_url_review(self):
        frame = ttk.LabelFrame(self.url_review_container, text=f"URL Review {len(self.url_reviews) + 1}")
        frame.pack(fill='x', padx=5, pady=5)

        ttk.Label(frame, text="URL:").pack(anchor='w', padx=5, pady=(5, 0))
        url_entry = ttk.Entry(frame, width=80)
        url_entry.pack(fill='x', padx=5)

        ttk.Label(frame, text="Effective URL:").pack(anchor='w', padx=5, pady=(5, 0))
        effective_url_entry = ttk.Entry(frame, width=80)
        effective_url_entry.pack(fill='x', padx=5)

        ttk.Label(frame, text="Results:").pack(anchor='w', padx=5, pady=(5, 0))
        results_text = scrolledtext.ScrolledText(frame, height=5)
        results_text.pack(fill='x', padx=5, pady=(0, 5))

        self.url_reviews.append({
            'frame': frame,
            'url': url_entry,
            'effective_url': effective_url_entry,
            'results': results_text
        })

    def remove_url_review(self):
        if self.url_reviews:
            last = self.url_reviews.pop()
            last['frame'].destroy()

    def is_ip(self, indicator):
        # Simple IP validation
        parts = indicator.split('.')
        return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)
    
    def check_urls(self):
        messagebox.showinfo("Info", "URL checking functionality would be implemented here")
    
    def check_ips(self):
        messagebox.showinfo("Info", "IP checking functionality would be implemented here")
    
    def check_hashes(self):
        messagebox.showinfo("Info", "Hash checking functionality would be implemented here")
    
    def parse_email_chain(self, raw_text):
        lines = [line.strip() for line in raw_text.strip().splitlines() if line.strip()]
        events = []
        for i in range(0, len(lines), 6):
            if i + 5 < len(lines):
                events.append(tuple(lines[i:i+6]))
        return events

    def format_email_chain(self):
        raw_text = self.email_chain_input.get("1.0", tk.END)
        events = self.parse_email_chain(raw_text)
        formatted = ["Email Chain:"]
        for e in events:
            timeline, source, event_type, result, threat, details = e
            formatted.append(f"{timeline} | {source} – {event_type}")
            formatted.append(f"  - Result: {result}")
            formatted.append(f"  - Threat: {threat}")
            formatted.append(f"  - Details: {details}")
        self.email_chain_input.delete("1.0", tk.END)
        self.email_chain_input.insert("1.0", "\n".join(formatted))
    
    # Defang Functions for Final Report
    def defang_domain(self, domain):
        if not domain:
            return domain
        return domain.replace('.', '[.]')

    def defang_ip(self, ip):
        if not ip:
            return ip

        if isinstance(ip, dict):
            if 'ip' in ip:
                ip = ip['ip'].get().strip() if hasattr(ip['ip'], 'get') else ip.get('ip', '')
            else:
                return str(ip)

        if isinstance(ip, (tk.Entry, ttk.Entry)):
            ip = ip.get().strip()

        if not isinstance(ip, str):
            return str(ip)

        # Check if it's a valid IPv4 address
        parts = ip.split('.')
        if len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
            return f"{parts[0]}.{parts[1]}.{parts[2]}[.]{parts[3]}"
        return ip  

    def defang_url(self, url):
        if not url:
            return url
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            if parsed.hostname:
                # Defang the hostname part
                defanged_host = parsed.hostname.replace('.', '[.]')
                # Reconstruct the URL
                netloc = parsed.netloc.replace(parsed.hostname, defanged_host)
                return parsed._replace(netloc=netloc).geturl()
            return url.replace('.', '[.]')
        except:
            # If URL parsing fails, just replace all dots
            return url.replace('.', '[.]')

    def compile_report(self):
        report = []
        report.append("[!] ==================== L1 INVESTIGATION ==================== [!]")

        # Conclusion
        conclusion_content = self.conclusion_text.get("1.0", tk.END).strip()
        if conclusion_content:
            report.append("[+] ----------------------- CONCLUSION ----------------------- [+]")
            report.append(conclusion_content)
            report.append("")

        # Triage
        triage_notes = self.triage_text.get("1.0", tk.END).strip()
        if triage_notes == "Leave it blank if there are no duplicates.":
            triage_notes = ""

        ids = [e['entry'].get().strip() for e in self.event_ids if e['entry'].get().strip()]
        if triage_notes or ids:
            report.append("[+] ------------------------- TRIAGE ------------------------- [+]")

            if triage_notes:
                report.append(triage_notes)

            if ids:
                if triage_notes:
                    report.append("")
                report.append("Event IDs:")
                for val in ids:
                    report.append(f"- {val}")

        else:
            report.append("[+] ------------------------- TRIAGE ------------------------- [+]")
            report.append("No duplicates found.")
  
        # Entities
        if self.entities['hosts'] or self.entities['users']:
            report.append("")
            report.append("[+] ------------------------ ENTITIES ------------------------ [+]")
        
            if self.entities['hosts']:
                report.append("Hosts:")
                for i, host in enumerate(self.entities['hosts'], 1):
                    hostname = host['entries']['hostname'].get()
                    local_ip = host['entries']['local_ip'].get()
                    os = host['entries']['os'].get()
                    if hostname:
                        report.append(f"  {i}. {hostname}")
                        if local_ip:
                            report.append(f"     Local IP: {local_ip}")
                        if os:
                            report.append(f"     OS: {os}")
                report.append("")
        
            if self.entities['users']:
                report.append("Users:")
                for i, user in enumerate(self.entities['users'], 1):
                    username = user['entries']['username'].get().strip()
                    job_title = user['entries']['job_title'].get().strip()
                    company = user['entries']['company'].get().strip()
                    signin_logs = user['entries']['signin_logs'].get().strip()
                    audit_logs = user['entries']['audit_logs'].get().strip()
                    if username:
                        report.append(f"  {i}. {username}")
                        if job_title:
                            report.append(f"     Job Title: {job_title}")
                        if company:
                            report.append(f"     Company: {company}")
                        if signin_logs:
                            report.append(f"     Entra ID Sign-in Logs: {signin_logs}")
                        if audit_logs:
                            report.append(f"     Entra ID Audit Logs: {audit_logs}")
    
        # Tanium Investigations
        if self.tanium_investigations:
            report.append("")
            report.append("[+] ------------------ TANIUM INVESTIGATION ------------------ [+]")
            for idx, intel in enumerate(self.tanium_investigations, start=1):
                intel_event = intel['intel'].get().strip()
                if not intel_event:
                    continue
                report.append(f"→ Intel Event {idx}: {intel_event}")
                for h_idx, host in enumerate(intel['hosts'], start=1):
                    hn = host['hostname'].get().strip()
                    ac = host['action'].get().strip()
                    cmd = host['command'].get("1.0", tk.END).strip()
                    ts = host['timestamp'].get().strip()
                    cp = host['child_proc'].get().strip()
                    ch = host['child_hash'].get().strip()
                    cr = host.get('child_reputation', '')
                    pp = host['parent_proc'].get().strip()
                    ph = host['parent_hash'].get().strip()
                    pr = host.get('parent_reputation', '')
                    pt = host['tree'].get("1.0", tk.END).strip()
                    fa = host['file_activity'].get("1.0", tk.END).strip()
                    rc = host['reg_changes'].get("1.0", tk.END).strip()
                    na = host['net_activity'].get("1.0", tk.END).strip()
                    dns = host['dns_calls'].get("1.0", tk.END).strip()
                    add = host['additional_info'].get("1.0", tk.END).strip()

                    report.append(f"  Host {h_idx}: {hn}")
                    if ac: report.append(f"  Action Taken: {ac}")
                    if cmd: report.append(f"  Command: {cmd}")
                    if ts: report.append(f"  Timestamp: {ts}")
                    if cp: report.append(f"  Child Process: {cp}")
                    if ch: report.append(f"  - SHA256: {ch}")
                    if cr: report.append(f"    ↳ {cr}")
                    if pp: report.append(f"  Parent Process: {pp}")
                    if ph: report.append(f"  - SHA256: {ph}")
                    if pr: report.append(f"    ↳ {pr}")
                    if pt: 
                        tree_lines = pt.split('\n')
                        if tree_lines and tree_lines[0].strip():
                            report.append("  Process Tree:")
                            for line in tree_lines:
                                if line.strip():
                                    report.append(f"  {line}")
                    if fa: report.append(f"  File Activity:\n  {fa}")
                    if rc: report.append(f"  Registry Changes:\n  {rc}")
                    if na: report.append(f"  Network Activity:\n  {na}")
                    if dns: report.append(f"  DNS Calls:\n  {dns}")
                    if add: report.append(f"  Additional Info:\n  {add}")

        # MDE Investigations
        if self.mde_investigations:
            report.append("")
            report.append("[+] ----------------- DEFENDER INVESTIGATION ----------------- [+]\n")
            for inv_num, inv in enumerate(self.mde_investigations, start=1):
                sig = inv['signature'].get().strip()
                if sig:
                    report.append(f"→ Signature: {sig}")
                for link_obj in inv['links']:
                    lnk = link_obj['link'].get("1.0", tk.END).strip()
                    res = link_obj['result'].get("1.0", tk.END).strip()
                    if lnk:
                        report.append(f"  Link: {lnk}")
                        if res:
                            report.append(f"  Result: {res}")

        # C2/Bad Rep Domain Investigation
        c2_count = self.c2_count.get()
        c2_user_identity = self.c2_user_identity.get()
        if c2_count or c2_user_identity or self.c2_domains or self.c2_ips:
            report.append("")
            report.append("[+] -------------------- C2 INVESTIGATION -------------------- [+]")
            if self.c2_domains:
                report.append("Destination Domains:")
                for i, domain in enumerate(self.c2_domains, 1):
                    domain_name = domain['domain'].get()
                    results = domain['results'].get()
                    if domain_name:
                        defanged_domain = self.defang_domain(domain_name)
                        report.append(f"  {i}- {defanged_domain}")
                        if results:
                            report.append(f"     ↳ {results}")
        
            if self.c2_ips:
                report.append("Destination IPs:")
                for i, ip in enumerate(self.c2_ips, 1):
                    ip_addr = ip['ip'].get()
                    results = ip['results'].get("1.0", tk.END).strip()
                    if ip_addr:
                        defanged_ip = self.defang_ip(ip_addr)
                        report.append(f"  {i}- {defanged_ip}")
                    if results:
                        for line in results.split('\n'):
                            if line.strip():
                                report.append(f"     ↳ {line.strip()}")
            
            if c2_count:
                report.append(f"Count: {c2_count}")
            if c2_user_identity:
                report.append(f"User Identity: {c2_user_identity}")
    
        # Phishing Investigation
        email_has_content = any(field.get() for field in self.email_fields.values())
        if email_has_content or self.phishing_ips or self.phishing_links or self.attachments:
            report.append("")
            report.append("[+] ------------------------ PHISHING ------------------------ [+]")

            report.append("Email Details:")
            # Standard Fields
            for field_key, field_label in [
                ('email_date', 'Date'),
                ('sender_address', 'Sender Address'),
                ('sender_display', 'Sender Display Name'),
                ('return_path', 'Return Path'),
                ('reply_to', 'Reply-To'),
                ('recipients', 'Recipients')
            ]:
                value = self.email_fields[field_key].get()
                if value:
                    report.append(f"  {field_label}: {value}")

            # IPs
            for ip in self.phishing_ips:
                ip_addr = ip['ip'].get()
                ip_type = ip['type'].get()
                results = ip['results'].get("1.0", tk.END).strip()
                if ip_addr:
                    defanged_ip = self.defang_ip(ip_addr)
                    report.append(f"  {ip_type or 'IP'}: {defanged_ip}")
                    if results:
                        for line in results.splitlines():
                            report.append(f"    ↳ {line}")

            # Auth protocols
            spf = self.spf_result.get()
            dkim = self.dkim_result.get()
            dmarc = self.dmarc_result.get()
            if spf or dkim or dmarc:
                report.append(f"  Authentication Protocols: SPF={spf or 'N/A'}, DKIM={dkim or 'N/A'}, DMARC={dmarc or 'N/A'}")

            # Delivery Locations
            orig = self.original_delivery.get()
            latest = self.latest_delivery.get()
            if orig:
                report.append(f"  Original Delivery Location: {orig}")
            if latest:
                report.append(f"  Latest Delivery Location: {latest}")

            # Threat Label
            threat = self.threat_label.get()
            if threat and threat.lower() != "none":
                report.append(f"  Threat: {threat.upper()}")

            # Links
            if self.phishing_links:
                report.append(f"  Links:")
                for link in self.phishing_links:
                    url = link['url'].get()
                    defanged_url = self.defang_url(url)
                    results = link['results'].get("1.0", tk.END).strip() if isinstance(link['results'], scrolledtext.ScrolledText) else link['results'].get()
                    if url:
                        report.append(f"  - {defanged_url}")
                        if results:
                            for line in results.splitlines():
                                report.append(f"    ↳ {line}")

            # Attachments
            if self.attachments:
                report.append(f"  Attachments:")
                for i, attachment in enumerate(self.attachments, 1):
                    filename = attachment['filename'].get()
                    hash_val = attachment['hash'].get()
                    results = attachment['results'].get()
                    if filename:
                        report.append(f"    {i}. {filename}")
                        if hash_val:
                            report.append(f"       SHA256: {hash_val}")
                        if results:
                            report.append(f"       Analysis: {results}")

            # Email Chain
            chain = self.email_chain_input.get("1.0", tk.END).strip()
            if chain:
                report.append("")
                report.append(chain)

            # Additional Info
            additional_content = self.additional_info.get("1.0", tk.END).strip()
            if additional_content:
                report.append("")
                report.append("Additional Information:")
                report.append(additional_content)

        # Queries
        if self.queries:
            report.append("")
            report.append("[+] ---------------------- QUERIES USED ---------------------- [+]")
            for i, query in enumerate(self.queries, 1):
                query_type = query['type'].get()
                query_content = query['query'].get("1.0", tk.END).strip()
                results = query['results'].get("1.0", tk.END).strip()
                if query_content:
                    report.append(f"Query {i}:")
                    if query_type:
                        report.append(f"  Type: {query_type}")
                    report.append(f"  Query: {query_content}")
                    if results:
                        report.append(f"  Results: {results}")

        # VM LAB
        if self.file_reviews or self.url_reviews:
            report.append("")
            report.append("[+] ------------------------- VM LAB ------------------------- [+]")

            for i, review in enumerate(self.file_reviews, 1):
                fname = review['filename'].get().strip()
                results = review['results'].get("1.0", tk.END).strip()
                content = review['content'].get("1.0", tk.END).strip()

                report.append(f"File Review {i}:")
                if fname:
                    report.append(f"  File Investigated: {fname}")
                if results:
                    report.append(f"  Results:\n  {results}")
                if content:
                    report.append(f"  File Content:\n  {content}")
                report.append("")

            for i, review in enumerate(self.url_reviews, 1):
                url = review['url'].get().strip()
                eff = review['effective_url'].get().strip()
                results = review['results'].get("1.0", tk.END).strip()

                report.append(f"URL Review {i}:")
                if url:
                    report.append(f"  URL: {url}")
                if eff:
                    report.append(f"  Effective URL: {eff}")
                if results:
                    report.append(f"  Results:\n  {results}")
                report.append("")

        report.append("[!] ==================== L1 INVESTIGATION ==================== [!]")
        
        return "\n".join(report)

def main():
    root = tk.Tk()
    app = SOCReportGenerator(root)
    root.mainloop()

if __name__ == "__main__":
    main()
