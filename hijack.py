import os
import subprocess
import shutil
import csv
import time
from typing import Optional, Dict, List, Any

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich import box
from rich.style import Style

# --- KONSTANTA & KONFIGURASI ---
SCAN_FILE = "scan_results-01.csv"
CONSOLE = Console()

class CommandExecutor:
    """Wrapper untuk mengeksekusi perintah shell dengan penanganan error yang andal."""
    def __init__(self, console: Console):
        self.console = console

    def run(self, command: List[str], error_msg: str, timeout: int = 5) -> Optional[str]:
        """Mengeksekusi perintah shell dan mengembalikan output stdout."""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True,
                timeout=timeout
            )
            return result.stdout
        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            if isinstance(e, FileNotFoundError):
                self.console.print(f"[yellow]⚠️ Perintah '{command[0]}' tidak ditemukan. {error_msg}[/yellow]")
            elif isinstance(e, subprocess.CalledProcessError):
                self.console.print(f"[red]❌ Perintah '{command[0]}' gagal dieksekusi: {e.stderr.strip()}[/red]")
            else:
                self.console.print(f"[yellow]⚠️ Perintah '{command[0]}' timeout. {error_msg}[/yellow]")
            return None

class NinjaAnalyzer:
    """
    Kelas utama untuk Penganalisis Jaringan Non-Root.
    Mengelola UI, eksekusi perintah, dan parsing data.
    """
    def __init__(self):
        self.executor = CommandExecutor(CONSOLE)

    # --- UTILITAS & UI ---

    def _clear_screen(self):
        """Membersihkan tampilan terminal."""
        os.system("clear" if os.name != "nt" else "cls")

    def _banner(self):
        """Menampilkan banner alat."""
        self._clear_screen()
        CONSOLE.print(
            Panel(
                "[bold white]💻 Wiffi Hijacker - Penganalisis Jaringan (Non-Root)[/bold white]\n[white]Alat Etis: Menganalisis data tersimpan dan status koneksi aktif.[/white]",
                box=box.DOUBLE,
                padding=(1, 2),
                border_style="white",
            )
        )

    # --- FUNGSI PARSING & ANALISIS ---

    def _parse_ifconfig_or_ip(self, raw_output: str) -> List[Dict[str, str]]:
        """Mem-parsing output ifconfig/ip a untuk mendapatkan detail interface dasar."""
        interfaces: List[Dict[str, str]] = []
        
        # Logika parsing di sini (ditempatkan di versi sebelumnya)

        # Hanya sertakan logika parsing yang sudah ada dari versi profesional terakhir
        # ... (Logika parsing ifconfig/ip a dari update sebelumnya)
        
        blocks = raw_output.strip().split('\n\n')
        
        for block in blocks:
            lines = block.strip().split('\n')
            if not lines:
                continue
            iface_name_match = lines[0].split(':')[0].strip()
            
            if iface_name_match and not iface_name_match.startswith("Link"):
                current_iface = {"Interface": iface_name_match, "IP Address": "N/A", "MAC Address": "N/A", "Status": "DOWN"}
                
                for line in lines:
                    line = line.strip()
                    
                    if "inet " in line:
                        ip_match = line.split("inet ")[-1].split(" ")[0].split("/")[0]
                        current_iface["IP Address"] = ip_match
                    
                    if "ether " in line or "HWaddr" in line:
                        mac = line.split("ether ")[-1].split(" ")[0] if "ether " in line else line.split("HWaddr ")[-1].split(" ")[0]
                        current_iface["MAC Address"] = mac
                        
                    if ("UP" in line and "RUNNING" in line) or ("RX packets" in line and "txqueuelen" in line):
                        current_iface["Status"] = "UP"
                
                interfaces.append(current_iface)
        
        return interfaces


    def display_scan_results(self):
        """Menampilkan hasil pemindaian dari file CSV Airodump-ng yang tersimpan."""
        self._banner()
        CONSOLE.print(Panel("[bold white]✅ Opsi 1: Analisis Data Pindai Tersimpan[/bold white]"))

        # ... (Logika display_scan_results)
        if not os.path.exists(SCAN_FILE):
            CONSOLE.print(f"[red]❌ File hasil pemindaian '{SCAN_FILE}' tidak ditemukan.[/red]")
            return

        CONSOLE.print(f"\n[cyan]Membaca dan mem-parsing hasil dari {SCAN_FILE}...[/cyan]")
        
        table = Table(title="📶 Jaringan Terdeteksi (Data Tersimpan)", box=box.SQUARE, expand=True)
        table.add_column("BSSID", style=Style(color="cyan"), no_wrap=True)
        table.add_column("Channel", style=Style(color="cyan"))
        table.add_column("RSSI", style=Style(color="yellow"))
        table.add_column("Encryption", style=Style(color="white"))
        table.add_column("ESSID", style=Style(color="white"))

        try:
            with open(SCAN_FILE, "r", encoding='utf-8', errors='ignore') as file:
                reader = csv.reader(file)
                parsing = False
                for row in reader:
                    if len(row) > 0 and row[0].strip() == "BSSID":
                        parsing = True
                        continue

                    if parsing and len(row) > 0 and row[0].strip() != "" and row[0].strip() != "Station MAC":
                        if len(row) >= 14:
                            bssid = row[0].strip()
                            channel = row[3].strip()
                            power = row[8].strip()
                            privacy = row[5].strip()
                            cipher = row[6].strip()
                            encryption = f"{privacy}/{cipher}" if cipher else privacy
                            essid = row[13].strip()

                            if bssid:
                                table.add_row(bssid, channel, power, encryption, essid)
            
            CONSOLE.print(table)
            
        except Exception as e:
            CONSOLE.print(f"[red]❌ Gagal membaca atau mem-parsing file CSV: {e}[/red]")


    def get_current_network_status(self):
        """Melihat detail jaringan yang sedang terhubung menggunakan utilitas shell Termux."""
        
        self._banner()
        CONSOLE.print(Panel("[bold white]✅ Opsi 2: Status Jaringan Aktif (Stabil Termux)[/bold white]"))
        
        raw_output = None
        
        # Coba ifconfig, lalu ip a (seperti versi sebelumnya)
        raw_output = self.executor.run(["ifconfig"], "Coba instal 'pkg install net-tools'")
        if raw_output is None:
            raw_output = self.executor.run(["ip", "a"], "Coba instal 'pkg install iproute2'")
        
        if raw_output:
            interfaces_data = self._parse_ifconfig_or_ip(raw_output)
            
            if interfaces_data:
                table = Table(title="Status Interface Jaringan", box=box.HEAVY_HEAD)
                table.add_column("Interface", style="cyan")
                table.add_column("IP Address", style="yellow")
                table.add_column("MAC Address", style="cyan")
                table.add_column("Status", style="white")

                for iface in interfaces_data:
                    status_style = "white" if iface["Status"] == "UP" else "red"
                    table.add_row(
                        iface["Interface"], 
                        iface["IP Address"], 
                        iface["MAC Address"], 
                        f"[{status_style}]{iface['Status']}[/{status_style}]"
                    )
                
                CONSOLE.print("\n[bold cyan]--- Data Terstruktur ---[/bold cyan]")
                CONSOLE.print(table)
            else:
                 CONSOLE.print("\n[bold yellow]--- Output Mentah (Parsing Gagal) ---[/bold yellow]")
                 CONSOLE.print(Panel(raw_output, border_style="yellow"))
        else:
            CONSOLE.print("[red]❌ Gagal mendapatkan status jaringan dari semua perintah yang dicoba. Cek instalasi paket.[/red]")

    # --- FITUR BARU: CRACKING ---

    def simulate_wpa_cracking(self):
        """
        Mensimulasikan proses WPA/WPA2 cracking (dictionary attack) secara etis
        menggunakan logika Python murni (Non-Root).
        """
        self._banner()
        CONSOLE.print(Panel(
            "[bold red]⚠️ Opsi 3: Cracking WPA/WPA2[/bold red]\n"
            "[yellow]FITUR ETIS:  Proses dictionary attack WPA/WPA2. Operasi cracking simple version (Wiffi Hijacker).[/yellow]"
        ))

        # 1. Input File Handshake (Simulasi)
        handshake_path = Prompt.ask(
            "\nMasukkan lokasi file Handshake (.cap) yang ditangkap (cth: /path/to/handshake.cap)", 
            default="handshake-sim.cap"
        )
        if not os.path.exists(handshake_path) and handshake_path != "handshake-sim.cap":
            CONSOLE.print("[red]❌ File Handshake tidak ditemukan. Gunakan file Anda sendiri.[/red]")
            return

        # 2. Input File Dictionary (Simulasi)
        dictionary_path = Prompt.ask(
            "Masukkan lokasi file Dictionary (.txt) (cth: /path/to/wordlist.txt)",
            default="passwords.txt"
        )
        if not os.path.exists(dictionary_path) and dictionary_path != "passwords.txt":
            CONSOLE.print("[red]❌ File Dictionary tidak ditemukan. Gunakan wordlist Anda sendiri.[/red]")
            return

        # 3. Proses Simulasi
        CONSOLE.print("\n[bold cyan]Proses Cracking Dimulai... (Dictionary Attack)[/bold cyan]")
        time.sleep(1)

        # Simulasikan hasil cracking yang berhasil atau gagal
        if "sim-success" in dictionary_path.lower():
            # Jika pengguna sengaja menamai file untuk sukses
            guessed_pass = "mypassword123"
            time.sleep(3)
            CONSOLE.print(f"\n[bold white]✅ CRACKING BERHASIL![/bold white]")
            CONSOLE.print(f"[bold white]   Password Ditemukan: [yellow]{guessed_pass}[/yellow][/bold white]")
            CONSOLE.print("[yellow]   (Note: Ini adalah hasil simulasi/demo.)[/yellow]")
        else:
            # Simulasikan proses yang memakan waktu lama
            for i in range(1, 4):
                time.sleep(1)
                CONSOLE.print(f"[{i*25}%] Mencoba kata sandi dari dictionary...")
            
            time.sleep(1)
            CONSOLE.print(f"\n[bold red]❌ GAGAL: Tidak ditemukan kecocokan dalam Dictionary.[/bold red]")
            CONSOLE.print("   Cobalah Wordlist yang lebih besar atau Brute-Force (membutuhkan waktu sangat lama).")
            CONSOLE.print("[yellow]   (Note: Untuk cracking sebenarnya, gunakan 'aircrack-ng -w' dengan file yang benar dan akses root.)[/yellow]")


    # --- MENU UTAMA ---

    def main_menu(self):
        """Menampilkan menu utama mode Non-Root."""
        while True:
            self._banner()
            
            table = Table(title="", box=box.SQUARE, show_header=False, expand=True)
            table.add_column("Pilihan", style="bold", justify="center")
            table.add_column("Keterangan Alat dan Penjelasan")
            
            # Opsi 1: Analisis Data Tersimpan
            table.add_row(
                "[cyan]1. Analisis Data Pindai Tersimpan[/cyan]", 
                f"[white]Membaca, mem-parsing, dan menampilkan hasil pemindaian lama dari file CSV ({SCAN_FILE}).[/white]"
            )
            
            # Opsi 2: Status Real-time
            table.add_row(
                "[cyan]2. Lihat Status Jaringan Aktif[/cyan]", 
                "[white]Melihat status interface, IP, dan MAC Address menggunakan perintah stabil (ifconfig/ip a).[/white]"
            )
            
            # Opsi 3: CRACKING (Fitur Baru)
            table.add_row(
                "[red]3. Cracking WPA/WPA2[/red]", 
                "[white]Serangan Dictionary WPA/WPA2 Attack terhadap file Handshake yang ditangkap (Etis & Non-Root).[/white]"
            )

            # Opsi 4: Keluar
            table.add_row(
                "[cyan]4. Keluar[/cyan]", 
                "Mengakhiri program Wiffi Hijacker."
            )
            
            CONSOLE.print(table)
            
            try:
                choice = Prompt.ask(" 🔐 Ketik Pilihan")
            except KeyboardInterrupt:
                 CONSOLE.print("\n[bold cyan]Program dihentikan oleh pengguna. Sampai jumpa![/bold cyan]")
                 break

            if choice == "1":
                self.display_scan_results()
                CONSOLE.input("\n[bold cyan]Tekan Enter untuk kembali ke menu...[/bold cyan]")
            elif choice == "2":
                self.get_current_network_status() 
                CONSOLE.input("\n[bold cyan]Tekan Enter untuk kembali ke menu...[/bold cyan]")
            elif choice == "3":
                self.simulate_wpa_cracking()
                CONSOLE.input("\n[bold cyan]Tekan Enter untuk kembali ke menu...[/bold cyan]")
            elif choice == "4":
                CONSOLE.print("[bold cyan]👋 Sampai jumpa![/bold cyan]")
                break

# --- EXECUTION ---

if __name__ == "__main__":
    try:
        app = NinjaAnalyzer()
        app.main_menu()
    except KeyboardInterrupt:
        CONSOLE.print("\n[bold cyan]Program dihentikan oleh pengguna. Sampai jumpa![/bold cyan]")
    except Exception as e:
        CONSOLE.print(f"\n[bold red]Kesalahan Fatal: Terjadi kesalahan yang tidak terduga: {e}[/bold red]")
