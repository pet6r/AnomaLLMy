# AnomaLLMy: LLM-Powered Network Anomaly Detection & Analysis for Small and Medium-Sized Businesses

AnomaLLMy utilizes the power of Local Large Language Models (LLMs) via Ollama to enhance network security monitoring for **SMB environments**. It automates the detection of anomalous network connections based on your business's specific baselines and harnesses LLMs to provide contextual analysis and generate actionable reports for IT administrators.

### Core Workflow:

1.  **Baseline Creation:** Define your business network's known devices (by OUI - e.g., printers, servers, employee laptops, routers) and allowed network protocols (e.g., TCP, UDP, DNS, HTTPS). Generate baseline pickle files.
2.  **Detection:** Run the detector script to capture live network traffic. It compares traffic against your baseline and logs anomalous connections (those involving unknown devices or disallowed protocols) to timestamped CSV files.
3.  **LLM Analysis:** Run the analyzer script. It reads the anomalous connection CSVs, groups related conversations, queries your local Ollama LLM for detailed analysis (device identification, risk assessment, recommendations) for each group, and saves the detailed text output.
4.  **Report Generation:** Run the report generator script to parse the LLM's text output and create formatted `.docx` reports summarizing the findings for each anomaly log file.
5.  **(Optional) Metrics & Token Analysis:** Use the provided Jupyter notebooks to visualize LLM performance metrics and estimate token input usage.

## Project Structure
```bash
└── AnomaLLMy/
    ├── README.md
    ├── LICENSE
    ├── requirements.txt
    ├── analyzer/
    │   ├── anomaly_ollama_analyzer.py
    │   ├── create_docx_report.py
    │   ├── analysis_results/
    │   └── docx_reports/
    │
    ├── baseline/
    │   ├── create_comprehensive_oui.py
    │   ├── create_oui_baseline.py
    │   ├── create_protocol_baseline.py
    │   ├── manuf
    │   └── pickle_files/
    │       ├── oui_baseline.pkl
    │       ├── oui_comprehensive.pkl
    │       └── protocol_baseline.pkl
    ├── detector/
    │   ├── network_anomaly_detector.py
    │   └── anomaly_logs/
    │       └── anomalies_mock_connections.csv
    └── notebooks/
        ├── MetricAnalysis.ipynb
        └── TokenCounter.ipynb
```

## Setup

Follow these steps to set up your environment for AnomaLLMy:

### Prerequisites

*   Python 3.10 or higher
*   pip (Python package installer)
*   Git
*   Npcap **(for Windows packet capture)**  *Install Npcap separately on Windows before installing requirements.* ([https://npcap.com/](https://npcap.com/))
*   **(Optional)** Jupyter Lab or Jupyter Notebook for running the `.ipynb` files.

### 1. Clone the Repository

```bash
git clone https://github.com/IAES-Repo/AnomaLLMy.git
cd AnomaLLMy
```
### 2. Create and Activate Virtual Environment
It is recommended to use a virtual environment.
```bash
# Create the environment
python3 -m venv AnomaLLMy-venv

# Activate the environment
# Windows (cmd/powershell):
AnomaLLMy-venv\Scripts\activate

# macOS / Linux (bash/zsh):
source AnomaLLMy-venv/bin/activate
```

### 3. Install Dependencies
Ensure your virtual environment is active.

```bash
# Upgrade pip first (good practice)
pip install --upgrade pip

# Install required packages
pip install -r requirements.txt
```

### 4. Ollama Installation & Setup
AnomaLLMy relies on a running Ollama instance to interact with local LLMs. This allows analysis without sending data to external cloud services or requiring an internet connection.
1. **Install Ollama**: Download and install from https://ollama.com/download.
2. **Verify Installation**: Open a new terminal (after installation) and `run ollama --version`
3. **Download Models**: Pull the LLM models you intend to use. The scripts default to `dolphin-llama3:8b`, but you can specify others. Consider models known for good reasoning or instruction following.

 ```bash
# Example: Download the default model
ollama pull dolphin-llama3:8b

# Example: Download another popular model
ollama pull granite3.1-dense:2b

# Listing your models
ollama list

# Ollama help
ollama help
```
4. **Ensure Ollama is Running**: Ollama usually runs as a background service. Check its status or start it if necessary according to its documentation.

## Usage
Execute the following steps in order. Remember to keep your virtual environment activated.

### Step 1: Create Baseline Files
These define what is considered "normal" for your specific business network.

1. **Comprehensive OUI Lookup - Run Once/Occasionally**:
- Download the manuf file from Wireshark (https://www.wireshark.org/download/automated/data/). This helps identify unknown devices later.
- Navigate to the `baseline/` directory: `cd baseline`
- Run the script to create the large lookup pickle:

```bash
# Replace /path/to/manuf.txt with the actual path to your downloaded file
python3 create_comprehensive_oui.py -i /path/to/manuf.txt -o ./pickle_files/oui_comprehensive.pkl
```

2. **Organizational Whitelists - Customize & Run**:
- Edit create_oui_baseline.py: Modify the KNOWN_OUI_MFG_DATA dictionary to include OUIs of devices you trust on your network (e.g., your specific router brand, printers, servers, known laptop manufacturers used by employees).
- Edit create_protocol_baseline.py: Modify the set of allowed protocol strings (e.g., {"TCP", "UDP", "ARP", "ICMP", "DNS", "HTTP", "HTTPS"}). Be specific to what your business needs.
- Run the scripts from the `baseline/` directory:

```bash
python create_oui_baseline.py -o ./pickle_files/oui_baseline.pkl
python create_protocol_baseline.py -o ./pickle_files/protocol_baseline.pkl
```
- Navigate back to the project root with following command: `cd ..`

### Step 2. Run the Network Anomaly Detector
This script captures traffic and generates anomaly CSVs based on your baseline.

1. Navigate to the `detector/` directory with following command: `cd detector`
2. Run the script. **This will require Administrator/sudo privileges for live capture**. Choose the network interface connected to your main business network segment.

```bash
# Ensure your python environment is still active

# Example (macOS/Linux): Replace 'en0' with your interface name
sudo python3 continuous_network_anomaly_detector.py -i en0 -t 10 -o ./anomaly_logs/

# Example (Windows): Replace 'Ethernet' with your interface name found via Scapy/ipconfig
# Run from an Administrator Command Prompt/PowerShell
python3 continuous_network_anomaly_detector.py -i Ethernet -t 10 -o ./anomaly_logs/
```
- -i <interface>: Specifies the network interface to monitor (required).
- -t <minutes>: Sets the interval (in minutes) between CSV exports (default: 10).
- -o <directory>: Specifies where to save the output CSV files (default: ./anomaly_logs/).
- Uses baseline files from ../baseline/pickle_files/ by default. Use -ob, -pb, -cb to override paths if needed.

3. Let it run to capture anomalies. **Press Ctrl+C to stop gracefully**. CSV files will appear in anomaly_logs/.
4. Navigate back to the project root: `cd ..`

### Step 3: Run the LLM Analyzer
This script processes the anomaly CSVs and generates detailed text analyses using your local Ollama LLM.
1. Navigate to the analyzer/ directory: `cd analyzer`
2. Ensure your Ollama service is running with the desired model downloaded.
3. Run the analyzer script:

```bash
# Analyze the latest anomaly CSV found in ../detector/anomaly_logs/
python3 anomaly_ollama_analyzer.py --mode latest

# Analyze ALL unanalyzed anomaly CSVs
# python3 anomaly_ollama_analyzer.py --mode all

# Analyze a specific anomaly CSV
# python3 anomaly_ollama_analyzer.py --mode file -f ../detector/anomaly_logs/anomalies_XYZ.csv

# Specify a different model, input, or output directory
# python3 anomaly_ollama_analyzer.py --mode latest -m mistral -d /path/to/csvs -o /path/to/save/analysis
```
- --mode: latest (default), all, or file.
- -f <filename>: Required if mode is file. Path relative to anomaly_dir.
- -m <model_name>: Specify Ollama model (default: dolphin-llama3:8b).
- -d <directory>: Override the directory containing anomaly CSVs (default: ../detector/anomaly_logs/).
- -o <directory>: Override the directory to save analysis TXT files (default: ./analysis_results/).

4. Analysis `.txt` files will appear in `analysis_results/`.
5. Navigate back to the project root: `cd ..`

### Step 4: Generate DOCX Reports
This script creates formatted Word documents from the text analysis files, suitable for review or sharing.
1. Navigate to the `analyzer/` directory: `cd analyzer`
2. Run the report generation script:

```bash
# Generate report for the latest analysis TXT file found in ./analysis_results/
python3 create_docx_report.py --mode latest

# Generate reports for ALL analysis TXT files
# python3 create_docx_report.py --mode all

# Generate report for a specific analysis TXT file
# python3 create_docx_report.py --mode file -f ./analysis_results/analysis_XYZ.txt

# Specify different input/output directories
# python3 create_docx_report.py --mode latest -i /path/to/analysis/txts -o /path/to/save/docx
```
- --mode: latest (default), all, or file.
- -f <filename>: Required if mode is file. Path relative to input-dir.
- -i <directory>: Override the directory containing analysis TXT files (default: ./analysis_results/).
- -o <directory>: Override the directory to save DOCX reports (default: ./docx_reports/).

3. .docx report files will appear in `docx_reports/`.
4. Navigate back to the project root: `cd ..`

### (Optional) Analysis Notebooks
1. Navigate to the notebooks/ directory: `cd notebooks`
2. Start Jupyter Lab or Notebook:
```bash
jupyter lab
# or
jupyter notebook
```

3. Open and run the cells in TokenCounter.ipynb (estimates LLM token input size) or Metric_Analysis.ipynb (visualizes LLM performance from analysis files). Adjust paths inside the notebooks if necessary.

## Customization
- **Baselines**: The effectiveness depends heavily on accurate `oui_baseline.pkl` and `protocol_baseline.pkl`. Regularly update these based on your known network assets (new employee laptops, printers, servers, IoT devices) and allowed traffic policies.
- **LLM Model**: Experiment with different Ollama models (-m flag). Smaller models are faster but might provide less detailed analysis; larger models offer more depth but require more resources.
- **Prompts**: Modify the instruction_prompt in `anomaly_ollama_analyzer.py` to tailor the LLM's analysis focus (e.g., emphasize certain protocols, ask different questions).
- **Detector Settings**: Adjust the capture interval (-t) and potentially add BPF filters (-f) in `network_anomaly_detector.py` for performance or specific targeting (e.g., filter out known noisy traffic).
