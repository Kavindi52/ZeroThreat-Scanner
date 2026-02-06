// script.js - ZeroThreat Scanner
// Client-side file analysis with heuristic detection

class ZeroThreatScanner {
    constructor() {
        this.dropZone = document.getElementById('dropZone');
        this.fileInput = document.getElementById('fileInput');
        this.resultsList = document.getElementById('resultsList');
        this.init();
    }

    init() {
        this.setupEvents();
    }

    setupEvents() {
        // Click to open file dialog
        this.dropZone.addEventListener('click', () => this.fileInput.click());

        // File input change
        this.fileInput.addEventListener('change', e => {
            if (e.target.files.length) this.startScan(e.target.files);
        });

        // Drag & drop
        ['dragover', 'dragenter'].forEach(eventName => {
            this.dropZone.addEventListener(eventName, e => {
                e.preventDefault();
                this.dropZone.classList.add('active');
            });
        });

        ['dragleave', 'drop'].forEach(eventName => {
            this.dropZone.addEventListener(eventName, e => {
                e.preventDefault();
                this.dropZone.classList.remove('active');
            });
        });

        this.dropZone.addEventListener('drop', e => {
            if (e.dataTransfer.files.length) {
                this.startScan(e.dataTransfer.files);
            }
        });
    }

    async startScan(fileList) {
        document.getElementById('dropZone').style.pointerEvents = 'none';
        document.getElementById('scanningArea').classList.remove('hidden');
        document.getElementById('resultsSection').classList.add('hidden');

        let safeCount = 0;
        let suspiciousCount = 0;
        let dangerCount = 0;

        this.resultsList.innerHTML = '';

        for (let i = 0; i < fileList.length; i++) {
            const file = fileList[i];
            const progress = Math.round(((i + 1) / fileList.length) * 100);

            document.getElementById('progressText').textContent = `${progress}%`;
            document.getElementById('progressFill').style.width = `${progress}%`;
            document.getElementById('currentFile').textContent = `Analyzing: ${file.name}`;

            await new Promise(r => setTimeout(r, 400 + Math.random() * 600)); // fake delay

            const result = await this.analyzeFile(file);

            this.renderResult(result);

            if (result.level === 'safe') safeCount++;
            else if (result.level === 'low' || result.level === 'medium') suspiciousCount++;
            else dangerCount++;
        }

        document.getElementById('safeCount').textContent = safeCount;
        document.getElementById('warningCount').textContent = suspiciousCount;
        document.getElementById('threatCount').textContent = dangerCount;

        // Finish
        setTimeout(() => {
            document.getElementById('scanningArea').classList.add('hidden');
            document.getElementById('resultsSection').classList.remove('hidden');
            this.dropZone.style.pointerEvents = 'auto';
        }, 800);
    }

    async analyzeFile(file) {
        const result = {
            name: file.name,
            size: file.size,
            level: 'safe',
            score: 0,
            findings: []
        };

        // 1. Basic extension vs magic bytes check
        const extension = (file.name.split('.').pop() || '').toUpperCase();
        let detectedType = 'UNKNOWN';

        try {
            const headerHex = await this.getFileHeaderHex(file);
            detectedType = this.detectFileType(headerHex);

            if (detectedType !== 'UNKNOWN' && detectedType !== extension) {
                result.score += 40;
                result.findings.push(`Possible extension spoofing: claims .${extension} but detected ${detectedType}`);
            }
        } catch (err) {
            result.findings.push('Could not read file header');
        }

        // 2. Simple heuristic string/pattern scan (only small files)
        if (file.size < 2 * 1024 * 1024) { // max 2 MB
            try {
                const text = await file.text();

                const rules = [
                    { pattern: /eval\s*\(/i, score: 35, msg: 'Suspicious use of eval()' },
                    { pattern: /fromCharCode/i, score: 30, msg: 'Possible encoded payload' },
                    { pattern: /keylogger|keystroke|hookkeyboard/i, score: 50, msg: 'Keylogger-like strings found' },
                    { pattern: /cmd\.exe|powershell\.exe/i, score: 25, msg: 'Windows command execution reference' },
                    { pattern: /base64_decode|atob\s*\(/i, score: 20, msg: 'Base64 decoding detected' },
                    { pattern: /http:\/\/|https:\/\/.*\.exe/i, score: 28, msg: 'Download link to .exe found' }
                ];

                for (const rule of rules) {
                    if (rule.pattern.test(text)) {
                        result.score += rule.score;
                        result.findings.push(rule.msg);
                    }
                }
            } catch (e) {
                // silent fail if not text file
            }
        }

        // Determine final threat level
        if (result.score >= 80) result.level = 'critical';
        else if (result.score >= 50) result.level = 'high';
        else if (result.score >= 25) result.level = 'medium';
        else if (result.score >= 10) result.level = 'low';
        else result.level = 'safe';

        return result;
    }

    async getFileHeaderHex(file) {
        return new Promise((resolve) => {
            const reader = new FileReader();
            reader.onload = e => {
                const bytes = new Uint8Array(e.target.result);
                let hex = '';
                for (let i = 0; i < Math.min(20, bytes.length); i++) {
                    hex += bytes[i].toString(16).padStart(2, '0').toUpperCase();
                }
                resolve(hex);
            };
            reader.readAsArrayBuffer(file.slice(0, 20));
        });
    }

    detectFileType(hex) {
        if (hex.startsWith('FFD8FF')) return 'JPG';
        if (hex.startsWith('89504E47')) return 'PNG';
        if (hex.startsWith('47494638')) return 'GIF';
        if (hex.startsWith('424D')) return 'BMP';
        if (hex.startsWith('25504446')) return 'PDF';
        if (hex.startsWith('4D5A')) return 'EXE';
        if (hex.startsWith('504B0304') || hex.startsWith('504B0506')) return 'ZIP';
        if (hex.startsWith('52617221')) return 'RAR';
        if (hex.startsWith('377ABCAF')) return '7Z';
        if (hex.startsWith('49492A00') || hex.startsWith('4D4D002A')) return 'TIF';
        if (hex.startsWith('25504446')) return 'PDF';
        if (hex.startsWith('D0CF11E0')) return 'DOC/XLS/PPT'; // OLE
        return 'UNKNOWN';
    }

    renderResult(result) {
        const card = document.createElement('div');
        card.className = `result-card ${result.level}`;

        card.innerHTML = `
            <h4>${result.name}</h4>
            <div style="color:#94a3b8; margin:0.4rem 0;">${this.formatBytes(result.size)}</div>
            <div class="level-badge ${result.level}">${result.level.toUpperCase()}</div>
            <div style="margin:0.8rem 0;">Score: <strong>${result.score}</strong></div>
            ${result.findings.length
                ? `<ul style="margin-top:0.8rem; padding-left:1.4rem; color:#f87171;">` +
                result.findings.map(f => `<li>${f}</li>`).join('') +
                `</ul>`
                : `<div style="color:#10b981; font-weight:500;">No suspicious patterns detected</div>`
            }
        `;

        this.resultsList.appendChild(card);
    }

    formatBytes(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }
}

// Start the scanner when page loads
document.addEventListener('DOMContentLoaded', () => {
    new ZeroThreatScanner();
});