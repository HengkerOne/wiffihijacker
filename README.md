# 💻 Wiffi Hijacker - Network Analyzer & Cracker (Non-Root Focus)

Wiffi Hijacker adalah alat berbasis Python yang dirancang untuk analisis jaringan pasif dan eksekusi cracking WPA/WPA2 secara *offline* (dictionary attack) pada lingkungan non-root, seperti Termux di Android atau lingkungan Linux/macOS standar.

Alat ini memanfaatkan pustaka `rich` untuk tampilan antarmuka yang profesional dan terstruktur.

## ⚠️ Peringatan Penting (Etika dan Legalitas)

Alat ini disediakan semata-mata untuk tujuan **edukasi, pengujian keamanan, dan pelatihan etika hacking** (pentesting).

* **JANGAN** gunakan alat ini untuk mengakses atau mengganggu jaringan yang bukan milik Anda atau yang Anda tidak memiliki izin tertulisnya.
* **Cracking** WPA/WPA2 adalah ilegal tanpa izin yang sah. Pengembang tidak bertanggung jawab atas penyalahgunaan alat ini.
* **Fitur Cracking (Opsi 3):** Membutuhkan file **Handshake (.cap)** yang sudah ditangkap dan perangkat harus sudah menginstal `aircrack-ng`.

## ✨ Fitur Utama

1.  **Analisis Data Pindai:** Membaca, mem-parsing, dan menampilkan data jaringan dari file CSV hasil *dump* (misalnya `scan_results-01.csv` dari Airodump-ng).
2.  **Status Jaringan Aktif:** Menampilkan status interface jaringan, IP Address, dan MAC Address saat ini (menggunakan `ifconfig` atau `ip a`).
3.  **Cracking WPA/WPA2 Profesional:**
    * Mengeksekusi perintah **`aircrack-ng`** yang sebenarnya.
    * Menampilkan status kemajuan *dictionary attack* menggunakan **Progress Bar** *real-time* yang keren (`rich`).
    * Penanganan *error* yang andal untuk eksekusi perintah shell.

## 🛠️ Persyaratan Instalasi

Alat ini dirancang untuk dijalankan di lingkungan Linux/Unix. **Termux (Android)** sangat direkomendasikan karena akses ke utilitas jaringan umum.

### 1. Instalasi Lingkungan Dasar (Termux)

Buka Termux dan jalankan perintah berikut:

```bash
# Update dan Upgrade Termux
pkg update && pkg upgrade -y

# Instal Python dan dependensi penting
pkg install python git

# Clone Repositori
git clone https://github.com/HengkerOne/wiffihijacker
cd wiffihijacker

# Instal pustaka Python yang dibutuhkan
pip install rich

python <NAMA_FILE_SKRIP_ANDA>.py 
# Contoh: python Hijacke.py

# Pastikan file ini ada di direktori Anda
ls 
# Contoh output: hijacker.py, scan_results-01.csv, wordlist.txt
