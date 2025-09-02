import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import requests
import threading
import random
import string
from urllib.parse import urljoin, urlparse
import time

# --- Global Variables ---
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
HEADERS = {"User-Agent": USER_AGENT}

# --- Main Application Class ---
class VulnerabilityScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("darkboss1bd - Advanced Web Vulnerability Scanner")
        self.root.geometry("900x700")
        self.root.resizable(False, False)
        self.root.configure(bg="#0d0d0d")

        self.create_banner()
        self.create_widgets()
        self.start_animation()

    def create_banner(self):
        banner_frame = tk.Frame(self.root, bg="#000000", height=80)
        banner_frame.pack(fill="x")
        banner_frame.pack_propagate(False)

        banner_text = "darkboss1bd"
        banner_label = tk.Label(
            banner_frame,
            text=banner_text,
            font=("Courier", 28, "bold"),
            fg="#00ff00",
            bg="#000000"
        )
        banner_label.pack(pady=20)

        subtitle = tk.Label(
            banner_frame,
            text="Advanced Web Vulnerability Scanner",
            font=("Arial", 10),
            fg="#55ff55",
            bg="#000000"
        )
        subtitle.pack()

    def create_widgets(self):
        # Input Frame
        input_frame = tk.Frame(self.root, bg="#111111", padx=10, pady=10)
        input_frame.pack(pady=10, fill="x")

        tk.Label(input_frame, text="Enter Website URL:", font=("Arial", 12), fg="white", bg="#111111").grid(row=0, column=0, sticky="w")
        self.url_entry = tk.Entry(input_frame, width=50, font=("Arial", 12), bg="#222222", fg="#00ff00", insertbackground="#00ff00")
        self.url_entry.grid(row=0, column=1, padx=10)

        self.scan_btn = tk.Button(input_frame, text="Scan Now", command=self.start_scan, bg="#00cc00", fg="white", font=("Arial", 10, "bold"), width=12)
        self.scan_btn.grid(row=0, column=2, padx=10)

        # Progress Bar
        self.progress = ttk.Progressbar(input_frame, orient="horizontal", length=300, mode="indeterminate")
        self.progress.grid(row=0, column=3, padx=10)

        # Output Frame
        output_frame = tk.Frame(self.root, bg="#111111")
        output_frame.pack(pady=10, fill="both", expand=True)

        tk.Label(output_frame, text="Scan Results:", font=("Arial", 12), fg="white", bg="#111111").pack(anchor="w", padx=10)

        self.result_area = scrolledtext.ScrolledText(
            output_frame,
            wrap=tk.WORD,
            height=25,
            bg="#000000",
            fg="#00ff00",
            font=("Courier", 10),
            insertbackground="#00ff00"
        )
        self.result_area.pack(padx=10, pady=10, fill="both", expand=True)

    def start_animation(self):
        self.canvas = tk.Canvas(self.root, bg="black", height=100, highlightthickness=0)
        self.canvas.pack(fill="x")
        self.particles = []
        self.running = True
        self.animate()

    def animate(self):
        if not self.running:
            return
        self.canvas.delete("all")
        chars = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
        w = self.root.winfo_width()
        if w <= 1:
            w = 800

        if random.random() < 0.3:
            x = random.randint(0, w)
            self.particles.append([x, 0])

        for particle in self.particles[:]:
            x, y = particle
            char = random.choice(chars)
            color = "#00ff00" if y < 60 else "#00aa00"
            self.canvas.create_text(x, y, text=char, fill=color, font=("Courier", 12))
            particle[1] += 10
            if y > 100:
                self.particles.remove(particle)

        self.root.after(100, self.animate)

    def start_scan(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("Input Error", "Please enter a valid URL!")
            return

        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        self.url_entry.delete(0, tk.END)
        self.url_entry.insert(0, url)

        self.result_area.delete(1.0, tk.END)
        self.result_area.insert(tk.END, "[*] Starting scan...\n")
        self.progress.start()

        # Run scan in a separate thread
        thread = threading.Thread(target=self.perform_scan, args=(url,), daemon=True)
        thread.start()

    def perform_scan(self, url):
        try:
            parsed_url = urlparse(url)
            domain = f"{parsed_url.scheme}://{parsed_url.netloc}"
            self.log(f"Target: {domain}\n")

            # Test connection
            try:
                resp = requests.get(domain, timeout=10, headers=HEADERS)
                self.log(f"[✓] Connected to {domain} | Status: {resp.status_code}")
            except Exception as e:
                self.log(f"[✗] Connection failed: {str(e)}")
                self.finalize_scan()
                return

            # Check SSL
            if domain.startswith("https"):
                self.log("[✓] SSL/TLS: Enabled (HTTPS)")
            else:
                self.log("[!] SSL/TLS: Not Enabled (HTTP)")

            # Check robots.txt
            robots_url = urljoin(domain, "robots.txt")
            try:
                r = requests.get(robots_url, timeout=10, headers=HEADERS)
                if r.status_code == 200:
                    self.log(f"[!] robots.txt found: {robots_url}")
                    lines = r.text.strip().splitlines()
                    for line in lines[:10]:
                        self.log(f"    {line}")
                else:
                    self.log("[✓] robots.txt not found.")
            except:
                self.log("[?] robots.txt: Not accessible.")

            # Common sensitive paths
            sensitive_paths = [
                "admin/", "login/", "wp-admin/", "phpmyadmin/", "cpanel/", "backup.sql", ".env", "config.php"
            ]
            self.log("\n[🔍] Checking common sensitive paths:")
            for path in sensitive_paths:
                full_url = urljoin(domain, path)
                try:
                    r = requests.get(full_url, timeout=10, headers=HEADERS)
                    if r.status_code == 200:
                        self.log(f"  [!] {full_url} -> {r.status_code}")
                    elif r.status_code in [401, 403]:
                        self.log(f"  [⚠] {full_url} -> {r.status_code} (Access Denied)")
                    else:
                        self.log(f"  [✓] {full_url} -> {r.status_code}")
                except:
                    self.log(f"  [✗] {full_url} -> Connection failed")

            # Check for common headers
            self.log("\n[🛡️] Security Headers Check:")
            headers = resp.headers
            sec_headers = {
                'X-Frame-Options': 'Missing',
                'X-Content-Type-Options': 'Missing',
                'Strict-Transport-Security': 'Missing (HSTS)',
                'Content-Security-Policy': 'Missing',
                'X-Permitted-Cross-Domain-Policies': 'Missing'
            }
            for h in sec_headers:
                if h in headers:
                    self.log(f"  [✓] {h}: {headers[h]}")
                    sec_headers[h] = "Present"
                else:
                    self.log(f"  [!] {h}: {sec_headers[h]}")

            # Final notes
            self.log("\n[✅] Scan completed. Use results responsibly.")

        except Exception as e:
            self.log(f"[❌] An error occurred: {str(e)}")
        finally:
            self.finalize_scan()

    def log(self, message):
        self.result_area.insert(tk.END, message + "\n")
        self.result_area.see(tk.END)
        self.root.update_idletasks()

    def finalize_scan(self):
        self.progress.stop()
        self.log("\n--- Scan Finished ---\n")

    def on_closing(self):
        self.running = False
        self.root.destroy()


# --- Run Application ---
if __name__ == "__main__":
    root = tk.Tk()
    app = VulnerabilityScanner(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()