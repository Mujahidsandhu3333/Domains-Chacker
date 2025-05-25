
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, simpledialog
import pandas as pd
import requests
import threading
import tldextract

def normalize_domain(domain):
    ext = tldextract.extract(domain)
    return f"{ext.domain}.{ext.suffix}"

def is_meaningful_redirect(original, final):
    orig_norm = normalize_domain(original)
    final_parsed = requests.utils.urlparse(final)
    final_norm = normalize_domain(final_parsed.hostname or "")
    if orig_norm != final_norm:
        return True
    return final_parsed.path not in ["", "/"]

def check_domain(domain, output_box, results_list, keyword=None):
    domain = domain.strip()
    result = {
        "Domain": domain,
        "Reachable": "No",
        "Redirects To": "No",
        "Keyword Found": "N/A"
    }
    try:
        response = requests.get("http://" + domain, timeout=5, allow_redirects=True)
        result["Reachable"] = "Yes"
        if is_meaningful_redirect(domain, response.url):
            result["Redirects To"] = response.url
        else:
            result["Redirects To"] = "No"

        if keyword:
            try:
                if keyword.lower() in response.text.lower():
                    result["Keyword Found"] = "Yes"
                else:
                    result["Keyword Found"] = "No"
            except Exception:
                result["Keyword Found"] = "Error"
    except Exception:
        pass

    results_list.append(result)
    output_line = f"{result['Domain']:40} | {result['Reachable']:9} | {result['Redirects To']:30} | {result['Keyword Found']}"
    output_box.insert(tk.END, output_line + "\n")
    output_box.see(tk.END)

def process_domains(domains, output_box, keyword=None):
    results = []
    output_box.delete("1.0", tk.END)
    output_box.insert(tk.END, "Checking domains...\n")
    output_box.insert(tk.END, f"{'Domain':40} | {'Reachable':9} | {'Redirects To':30} | Keyword Found\n")
    output_box.insert(tk.END, "-"*110 + "\n")

    for domain in domains:
        if domain:
            check_domain(domain, output_box, results, keyword)

    df = pd.DataFrame(results)
    df.to_csv("domain_check_results.csv", index=False)
    messagebox.showinfo("Done", "Results saved to domain_check_results.csv")

def handle_text_input():
    domains = input_box.get("1.0", tk.END).splitlines()
    keyword = simpledialog.askstring("Keyword Search", "Enter a keyword to search in page (optional):")
    threading.Thread(target=process_domains, args=(domains, output_box, keyword)).start()

def handle_file_upload():
    file_path = filedialog.askopenfilename(filetypes=[("Text or Excel files", "*.txt *.xlsx")])
    if not file_path:
        return
    try:
        if file_path.endswith(".txt"):
            with open(file_path, "r") as f:
                domains = [line.strip() for line in f.readlines()]
        elif file_path.endswith(".xlsx"):
            df_input = pd.read_excel(file_path)
            domains = df_input.iloc[:, 0].dropna().tolist()
        else:
            messagebox.showerror("Error", "Unsupported file type.")
            return
        keyword = simpledialog.askstring("Keyword Search", "Enter a keyword to search in page (optional):")
        threading.Thread(target=process_domains, args=(domains, output_box, keyword)).start()
    except Exception as e:
        messagebox.showerror("Error", str(e))

# GUI setup
root = tk.Tk()
root.title("Domain Status & Keyword Checker")
root.geometry("1000x700")

tk.Label(root, text="Paste domains below (one per line):").pack(pady=5)
input_box = scrolledtext.ScrolledText(root, height=10)
input_box.pack(fill=tk.BOTH, padx=10, pady=5, expand=True)

tk.Button(root, text="Check Pasted Domains", command=handle_text_input).pack(pady=5)
tk.Button(root, text="Upload File", command=handle_file_upload).pack(pady=5)

tk.Label(root, text="Results:").pack(pady=5)
output_box = scrolledtext.ScrolledText(root, height=20)
output_box.pack(fill=tk.BOTH, padx=10, pady=5, expand=True)

root.mainloop()
