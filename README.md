# ZeroThreat Scanner 🔍🛡️

**ZeroThreat Scanner** is a **client-side**, privacy-first file analysis tool that helps detect potential security threats in files — **without uploading anything to a server**.

It performs basic heuristic checks such as:

- File type / extension mismatch (spoofing detection via magic bytes)
- Suspicious string patterns (eval, keylogger references, base64 decoding, etc.)
- Simple threat scoring system

Built with **HTML, CSS, and pure JavaScript** — no external frameworks or backend required.

https://github.com/YOUR-USERNAME/zerothreat-scanner

## ✨ Features

- **100% client-side** — your files never leave your browser
- Modern dark cyber-themed interface with cyan/blue accents
- Drag & drop or click to upload multiple files
- Real-time animated scanning progress
- Extension spoofing detection (magic bytes header check)
- Heuristic pattern matching for suspicious code/behavior
- Clear threat level classification (Safe / Low / Medium / High / Critical)
- Detailed per-file report with findings
- Responsive design (works on desktop and mobile)

## 🚀 Demo

You can try it live here:  
🔗 



## 🛠️ Tech Stack

- HTML5
- CSS (custom, no framework)
- Vanilla JavaScript
- File API (FileReader)
- Font Awesome icons
- Local browser only – zero dependencies to install

## ⚡ Quick Start

### Option 1: Open directly

1. Download or clone the repository
2. Double-click `index.html`  
   → opens in your default browser

### Option 2: Run with local server (recommended)

```bash
# Clone the repo
git clone https://github.com/YOUR-USERNAME/zerothreat-scanner.git

# Go into the folder
cd zerothreat-scanner

# Option A – Python 3
python -m http.server 8000

# Option B – Node.js (if you have npx)
npx serve

# Option C – Python 2 (older systems)
python -m SimpleHTTPServer 8000
