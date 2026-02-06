# ZeroThreat Scanner 🔍🛡️

**ZeroThreat Scanner** is a **client-side**, privacy-first file analysis tool that helps detect potential security threats in files — **without uploading anything to a server**.

It performs basic heuristic checks such as:

- File type / extension mismatch (spoofing detection via magic bytes)
- Suspicious string patterns (eval, keylogger references, base64 decoding, etc.)
- Simple threat scoring system

Built with **HTML, CSS, and pure JavaScript** — no external frameworks or backend required.

(https://github.com/Kavindi52/ZeroThreat-Scanner.git)

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
🔗 https://github.com/Kavindi52/ZeroThreat-Scanner.git


## 🛠️ Tech Stack

- HTML5
- CSS (custom, no framework)
- Vanilla JavaScript
- File API (FileReader)
- Font Awesome icons
- Local browser only – zero dependencies to install

Project Structure

zerothreat-scanner/
├── index.html          # Main page & UI
├── style.css           # All styling
├── script.js           # Scanning logic & file analysis
├── README.md

🔍 How It Works (in short)

User drops or selects files
File header (magic bytes) is read → checks if extension matches real file type
For small files (< 2 MB): content is scanned for suspicious patterns
Threat score is calculated
Results are shown with color-coded threat levels

Important note: This is not a full antivirus.
It uses very basic heuristic rules for educational and demonstration purposes only.

🙋‍♂️ Contributing
Contributions are welcome!
Possible improvements:

More file signatures / magic bytes
Better pattern database
File icon previews
Export report (JSON / PDF)
Dark / light mode toggle
Support larger files via chunk reading
Animated background effects
Better mobile experience

⚠️ Disclaimer
ZeroThreat Scanner is not a replacement for professional antivirus software.
It is an educational / proof-of-concept tool with very limited detection capabilities.
Always use trusted, up-to-date security software for real protection.

Made with 💻 & 🔒 by kavindi
textFeel free to change:

 My GitHub kavindi52 / ZeroThreat Scanner


Let me know if you want to add sections like:
- Roadmap
- Limitations & future ideas
- How to add new detection rules
- Deployment instructions (GitHub Pages, Netlify, Vercel, etc.)

Happy coding! 🚀
