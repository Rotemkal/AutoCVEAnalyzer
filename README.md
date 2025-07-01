# AutoCVEAnalyzer
A Python application that analyzes individual CVEs (Common Vulnerabilities and Exposures) for their relevance to the automotive industry using the NVD API and OpenAI's GPT-4.

## 🔍 Project Overview

**AutoCVEAnalyzer** is designed for cybersecurity researchers interested in automotive security vulnerabilities. The application provides an interactive command line interface to:

- **Add individual CVEs** by ID with automatic data fetching from NVD
- **Analyze CVE relevance** to automotive systems using GPT-4
- **Store and manage** CVEs in a local SQLite database
- **Filter and view** automotive-relevant vulnerabilities
- **Override AI decisions** using automotive keyword detection

The tool combines NVD data retrieval, GPT-4 analysis, and keyword-based filtering to build a curated database of automotive cybersecurity vulnerabilities.

---

## 📁 Project Structure

- `main.py`: Interactive CLI application with menu system for CVE management
- `nvd_client.py`: NVD API client for fetching CVE details, CVSS scores, and vendor information
- `gpt_analyzer.py`: OpenAI GPT-4 integration for severity assessment and automotive relevance analysis
- `autocve.db`: SQLite database (auto-created) storing analyzed CVEs

---

## 🚗 Automotive Detection

The system uses two methods to identify automotive-relevant CVEs:

### 1. Keyword-Based Detection
Automatically scans for automotive-related terms including:
- **Manufacturers**: `porsche`, `tesla`, `bmw`, `toyota`, `mercedes`,
- **Systems**: `ecu`, `can bus`, `obd`, `infotainment`, `adas`, `telematics`
- **Technologies**: `v2x`, `v2v`, `v2i`, `battery management`
- **Suppliers**: `bosch`, `continental`, `denso`, `aptiv`, `valeo`
- **Infrastructure**: `charging station`, `ev charger`

### 2. GPT-4 Analysis
Sends CVE data to OpenAI for intelligent assessment of:
- **Severity**: Critical/High/Medium/Low/not enough information
- **Automotive Relevance**: Yes/No

The system can override GPT decisions if automotive keywords are detected but GPT marked the CVE as non automotive.

---

## 🛠 Technologies Used

- **Python 3.x**
- **OpenAI GPT-4 API** (for intelligent analysis)
- **NVD REST API v2.0** (for CVE data retrieval)
- **SQLite** (for local data storage)
- **python-dotenv** (for secure API key management)
- **Regular expressions** (for data parsing and validation)

---

## ⚙️ Setup Instructions

1. **Clone the repository**
   bash:
   git clone <https://github.com/Rotemkal/AutoCVEAnalyzer.git>
   cd autocve-analyzer
   
2. **Install dependencies**
   bash: 
   pip install -r requirements.txt
   
3. **Create environment file**
   Create a `.env` file in the root directory:
   .env:
   OPENAI_API_KEY=your_openai_api_key_here
   NVD_API_KEY=your_nvd_api_key_here  # Optional but recommended  

4. **Run the application**
   bash: 
   python main.py

---

## 🎯 Usage

The application provides an interactive menu with the following options:

1. **📝 Add new CVE**: Enter a CVE ID (e.g., CVE-2024-1234) to fetch and analyze
2. **📋 List all CVEs**: Display all stored CVEs with summary information
3. **🚗 Automotive CVEs only**: Filter and show only automotive-relevant CVEs
4. **🚪 Exit**: Close the application

### Example Workflow:
1. Run `python main.py`
2. Choose option 1 to add a CVE
3. Enter CVE ID (format: CVE-YYYY-NNNN)
4. System fetches data from NVD and analyzes with GPT-4
5. Review results and confirm addition to database
6. Use options 2 or 3 to view stored CVEs

---

## 📊 Data Storage

The application automatically creates and manages a SQLite database (`autocve.db`) with the following fields:

- CVE ID and description
- Severity assessment
- Automotive relevance (Yes/No)
- CVSS score and attack vector
- Vendor information
- Published date
- Date added to database

---

## 🔧 API Requirements

### Required:
- **OpenAI API Key**: For GPT-4 analysis (paid service)

### Optional:
- **NVD API Key**: Recommended for higher rate limits (free from NIST)
Without an NVD API key, the application still works but may hit rate limits with frequent use.

---

## Limitations

- **Manual CVE Entry**: Currently processes one CVE at a time (no bulk import)
- **GPT Accuracy**: AI analysis may occasionally misclassify edge cases
- **Rate Limits**: NVD API has usage limits (mitigated with API key)
- **Network Dependency**: Requires internet connection for API calls
- **Cost**: OpenAI API usage incurs charges based on tokens used

---

## 🛡️ Disclaimer

This tool is for research and educational purposes. GPT-4 analysis may contain inaccuracies. Always validate critical security decisions with additional sources and expert analysis.

---

## 👩‍💻 Created By

**Rotem** — Computer Science student passionate about cybersecurity, AI, and automotive security. This project demonstrates the intersection of artificial intelligence and cybersecurity threat analysis.

---

## 📄 License

This project is for educational and research purposes only. It uses public data from the NVD and the OpenAI API in accordance with their respective terms of use.