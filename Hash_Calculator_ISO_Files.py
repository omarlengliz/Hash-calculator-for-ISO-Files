import tkinter as tk
from tkinter import filedialog, messagebox
import subprocess

def upload_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        calculate_hash(file_path)

def calculate_hash(file_path):
    selected_algorithm = hash_method.get()
    cmd = f'powershell Get-FileHash "{file_path}" -Algorithm {selected_algorithm} '
    result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
    hashout = result.stdout.strip().split("\n")[2].split("          ")[1].split("       ")[0]
    message = f"Le hash du fichier avec l'algorithme {selected_algorithm} est: \n{hashout.strip()}"

    if result.returncode == 0:
        hash_output.config(state='normal')
        hash_output.delete('1.0', tk.END)
        hash_output.insert(tk.END, message)
        hash_output.tag_add("algorithm", "1.36", f"1.{36+len(selected_algorithm)+1}")  
        hash_output.tag_add("hash_result", "2.0", "2.end")  
        hash_output.tag_config("algorithm", foreground="red")  
        hash_output.tag_config("hash_result", foreground="green")  
        hash_output.config(state='disabled')
    else:
        error_message = f"Error: {result.stderr}"
        print(error_message)

def verify_hash():
    original_hash = original_hash_entry.get().strip()
    calculated_hash = hash_output.get('2.0', 'end-1c').strip()  
    if original_hash.upper() == calculated_hash:
        messagebox.showinfo("Match", "Hashes match!")
    else:
        messagebox.showerror("Not Match", "Hashes do not match.")

root = tk.Tk()
root.iconbitmap('28791.ico')
root.title("ISO File Hash Calculator")

hash_methods = ["MD5", "SHA1", "SHA256", "SHA512"] 
hash_method_label = tk.Label(root, text="Selectionnez une methode de Hash :")
hash_method_label.pack()
hash_method = tk.StringVar(root)
hash_method.set(hash_methods[0])  
hash_method_menu = tk.OptionMenu(root, hash_method, *hash_methods)
hash_method_menu.pack(pady=5)

upload_button = tk.Button(root, text="Upload fichier et calculer  le Hash", command=upload_file)
upload_button.pack(pady=10)

hash_output = tk.Text(root, height=10, width=50)
hash_output.pack(padx=10, pady=5)
hash_output.config(state='disabled')

original_hash_label = tk.Label(root, text="Hash Originale :")
original_hash_label.pack()
original_hash_entry = tk.Entry(root, width=50)
original_hash_entry.pack(pady=5)

verify_button = tk.Button(root, text="Verifer Hash", command=verify_hash)
verify_button.pack(pady=5)

root.mainloop()
