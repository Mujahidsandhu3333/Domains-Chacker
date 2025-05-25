# Domain Status & Keyword Checker (GUI)

This is a Python GUI tool that allows users to check the availability, redirection behavior, and keyword presence of a list of domains. The tool accepts domain input via text box or file upload and saves the results to a CSV file.

---

## 🖥 Features

- GUI-based interface built with `tkinter`
- Check if a domain is reachable (`HTTP`)
- Detect meaningful redirections (to another domain or subdirectory)
- Search for a custom keyword in the webpage content
- Load domains from `.txt` or `.xlsx` files
- Save output as `domain_check_results.csv`

---

## ✅ Requirements

### Python Version:
- Python 3.7 or higher

### Required Python Libraries:
Install the dependencies using pip:
```bash
pip install pandas
pip install requests
pip install tldextract
pip install openpyxl
