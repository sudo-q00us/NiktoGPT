# NiktoGPT

**NiktoGPT** is a Python automation tool that enhances the classic Nikto web vulnerability scanner by integrating AI analysis via the OpenRouter API (DeepSeek Chat v3.1). It runs Nikto, extracts relevant findings, analyzes them using GPT, generates a detailed HTML report, and can send the report by email.

---

## 🔍 Features

- Automatically launch Nikto scans
- Parse and filter the .log file intelligently
- Analyze findings using the GPT model `deepseek/deepseek-chat-v3.1:free`
- Generate clean and structured HTML reports
- Optionally send reports via email (SMTP)

---

## 🧰 Requirements

- Python 3.8+
- Nikto installed on the system
- An [OpenRouter](https://openrouter.ai/) API key
- Internet connection (for AI analysis)
- SMTP access (optional, for email sending)

---

## 📦 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/niktoGPT.git
   cd niktoGPT

2. Install dependencies:
   ```bash
   pip install -r requirements.txt

3. Make sure nikto is installed:
   ```bash
   which nikto
   
4. If not installed, you can get it via:
   ```bash
   sudo apt install nikto

## ⚙️ Configuration

Open the script run_nikto.py and edit these variables near the top:
   ```python
   TARGET = "https://example.com/"
   REPORT_DIR = "/path/to/save/reports/"
   NIKTO_BIN = "/usr/bin/nikto"
   ```

Set your OpenRouter API key via terminal:
   ```bash
   export OPENROUTER_API_KEY="your_openrouter_api_key"
   ```
Edit SMTP settings in the script:
   ```python
   SMTP_CONFIG = {
    "server": "smtp.example.com",
    "port": 25,
    "use_ssl": False,
    "starttls": False,
    "username": None,
    "password": None,
    "from_addr": "nikto-reports@example.com",
    "to_addr": "admin@example.com",
}
```
## 🚀 Usage

Run the main script:
   ```bash
   python3 run_nikto.py
   ```
This will:

   1. Launch a Nikto scan

   2. Parse the generated .log file

   3. Send each finding to the AI for analysis

   4. Create a styled HTML report

   5. Send the report by email (if configured)

## 📨 Email Setup (Optional)

Make sure the SMTP config is valid. If your SMTP requires auth, provide username and password in the script.

If no authentication is required (internal SMTP server), leave those as None.

## 📁 Output

```.log```: raw Nikto log

```.html```: GPT-analyzed report

```.txt```: fallback plain report (if HTML fails)

All saved under the ```REPORT_DIR``` path.

## 🧪 Example Run
   ```bash
   export OPENROUTER_API_KEY="sk-your-apikey"
   python3 run_nikto.py
   ```
## 🛠 Troubleshooting

Nikto not found? Edit ```NIKTO_BIN``` in the script.

No results? Try a less filtered target or disable strict log filtering.

API errors? Check your internet and ```OPENROUTER_API_KEY```.

Email not sending? Try another SMTP server or test ```with use_ssl = True```.

