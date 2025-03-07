import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox
import itertools
import threading
import time
import datetime
from queue import Queue
from fpdf import FPDF

# Detect hashing algorithm automatically
def detect_algorithm(target_hash):
    hash_lengths = {32: 'MD5', 40: 'SHA-1', 64: 'SHA-256', 128: 'SHA-512'}
    return hash_lengths.get(len(target_hash), None)

# Load wordlist for dictionary attack
def dictionary_attack(target_hash, algorithm, wordlist_path):
    if not wordlist_path:
        return None
    try:
        with open(wordlist_path, "r", encoding="latin-1") as file:
            for password in file:
                password = password.strip()
                if hash_password(password, algorithm) == target_hash:
                    return password
    except FileNotFoundError:
        messagebox.showerror("Error", "Wordlist file not found.")
        return None
    return None

# Hashing function
def hash_password(password, algorithm):
    try:
        hash_func = getattr(hashlib, algorithm.replace('-', '').lower(), None)
        if not hash_func:
            raise ValueError("Unsupported hash algorithm")
        return hash_func(password.encode()).hexdigest()
    except Exception as e:
        return None

# Brute-force attack with optimized threading
def brute_force_attack(target_hash, algorithm, charset, max_length):
    result_queue = Queue()
    found_event = threading.Event()
    
    def worker(length):
        for attempt in itertools.product(charset, repeat=length):
            if found_event.is_set():
                return
            password = ''.join(attempt)
            if hash_password(password, algorithm) == target_hash:
                result_queue.put(password)
                found_event.set()
                return
    
    threads = []
    for length in range(1, max_length + 1):
        thread = threading.Thread(target=worker, args=(length,))
        thread.start()
        threads.append(thread)
    
    for thread in threads:
        thread.join()
    
    return result_queue.get() if not result_queue.empty() else None

# Generate Report and Log History
def generate_report(target_hash, algorithm, password, time_taken):
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_content = ("\n" "CRACKED PASSWORD REPORT" "\n"
                      "=====================================" "\n\n"
                      f" Date & Time       : {current_time}\n"
                      f"-------------------------------------\n"
                      f" Hash              : {target_hash}\n"
                      f"-------------------------------------\n"
                      f" Detected Algorithm: {algorithm}\n"
                      f"-------------------------------------\n"
                      f" Cracked Password  : {password if password else 'Not Found'}\n"
                      f"-------------------------------------\n"
                      f" Time Taken        : {time_taken:.2f} seconds\n"
                      "=====================================")
    
    with open("cracking_report.txt", "w") as txt_file:
        txt_file.write(report_content)
    
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.multi_cell(0, 10, report_content)
    pdf.output("cracking_report.pdf")
    
    # Store log history
    with open("cracking_log.txt", "a") as log_file:
        log_file.write(report_content + "\n\n")

# GUI Functions
def start_cracking():
    target_hash = hash_entry.get().strip()
    if not target_hash:
        messagebox.showerror("Error", "Please enter a hash value.")
        return
    
    algorithm = detect_algorithm(target_hash)
    if not algorithm:
        messagebox.showerror("Error", "Unable to detect hash algorithm.")
        return
    
    wordlist_path = filedialog.askopenfilename(title="Select Wordlist File", filetypes=[("Text Files", "*.txt")])
    
    result_label.config(text=f"Detected Algorithm: {algorithm}. Cracking in progress...")
    
    def run_attack():
        start_time = time.time()
        password = dictionary_attack(target_hash, algorithm, wordlist_path)
        if not password:
            password = brute_force_attack(target_hash, algorithm, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 6)
        end_time = time.time()

        result_label.config(text=f"Password found: {password} (Time: {end_time - start_time:.2f}s)" if password else "Password not found")
        generate_report(target_hash, algorithm, password, end_time - start_time)
        messagebox.showinfo("Report Generated", "Report saved as TXT and PDF.")
    
    threading.Thread(target=run_attack, daemon=True).start()

# GUI Setup
root = tk.Tk()
root.title("HashBreakX - A Fast Hash-Cracking Tool")
root.geometry("600x400")
root.configure(bg="#1E1E1E")

header_label = tk.Label(root, text="⚡ HashBreakX - A Fast Hash-Cracking Tool ⚡", font=("Impact", 18, "bold"), fg="#FF5733", bg="#1E1E1E")
header_label.pack(pady=10)

tk.Label(root, text="Enter Hash:", font=("Arial", 12), fg="white", bg="#1E1E1E").pack()
hash_entry = tk.Entry(root, width=50, font=("Arial", 12))
hash_entry.pack(pady=5)

tk.Button(root, text="Start Cracking", command=start_cracking, font=("Arial", 12, "bold"), bg="#FF5733", fg="white", padx=10, pady=5).pack(pady=10)

result_label = tk.Label(root, text="", font=("Arial", 12), fg="#FF5733", bg="#1E1E1E")
result_label.pack(pady=10)

root.mainloop()
