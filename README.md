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
