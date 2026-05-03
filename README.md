# Nist_Json_Tool: Security Vulnerability Analysis in Healthcare Using NIST NVD Data

![Nist Json Tool Banner](screenshots/dashboard.png)

## Description

**Nist_Json_Tool** is a Python-based research tool designed for the systematic analysis of Common Vulnerabilities and Exposures (CVE) data sourced from the NIST National Vulnerability Database (NVD). The tool focuses on **healthcare cybersecurity**, applying **BERT-based Natural Language Processing (NLP)** and **CVSSv3.1 scoring metrics** to identify, classify, and analyze security vulnerabilities affecting healthcare systems and medical devices.

Unlike general-purpose vulnerability scanners, this tool is specifically engineered for academic research and security analysis in the healthcare domain — enabling researchers, security professionals, and students to extract meaningful insights from large-scale NVD JSON datasets through automated CVE filtering, CVSS metric analysis, and CWE categorization.

This project was developed as a final-year B.Tech research project under the Computer Science and Engineering (Cyber Security) program at **SRM Institute of Science and Technology, NCR Campus**.

---

## Key Features

- **NIST NVD JSON Parsing**: Efficiently processes large-scale NVD JSON data feeds to extract CVE entries relevant to healthcare systems and medical devices.

- **BERT NLP Integration**: Leverages a pre-trained BERT model to classify and filter CVE descriptions based on healthcare-domain relevance, enabling intelligent keyword-aware vulnerability identification.

- **CVSSv3.1 Metric Analysis**: Extracts and analyzes CVSS Base Scores, Attack Vectors, Privileges Required, User Interaction, Scope, and Impact metrics to assess vulnerability severity in context.

- **CWE Categorization**: Maps CVEs to their corresponding Common Weakness Enumeration (CWE) categories to identify recurring vulnerability patterns in healthcare software and devices.

- **Healthcare Domain Filtering**: Applies domain-specific keyword filtering (e.g., DICOM, HL7, EHR, PACS, infusion pump, medical IoT) to isolate clinically relevant vulnerabilities from the broader NVD dataset.

- **Statistical Vulnerability Reporting**: Generates summary statistics including yearly CVE trends, average CVSS scores per CWE category, severity distribution, and software product frequency.

- **CSV Export**: Exports filtered CVE datasets, CWE summaries, and software product lists in CSV format for use in further analysis or academic reporting.

- **Reproducible Research Design**: Standardized input formats and configurable parameters ensure consistent, reproducible results across different research environments.

---

## Project Structure

```
Nist_Json_Tool/
│
├── DataSample/              # Sample NVD JSON data feeds
├── src/                     # Core source code
│   ├── parser.py            # NVD JSON parser
│   ├── bert_classifier.py   # BERT NLP classification module
│   ├── cvss_analyzer.py     # CVSSv3.1 metric extractor
│   ├── cwe_mapper.py        # CWE category mapper
│   └── exporter.py          # CSV export utility
├── outputs/                 # Generated CSV reports
├── requirements.txt         # Python dependencies
└── README.md
```

---

## Requirements

- Python 3.9+
- pip (Python package manager)
- Internet connection (for BERT model download on first run)

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/utkarshaman13/Nist_Json_Tool.git
cd Nist_Json_Tool
```

### 2. Create a Virtual Environment (Recommended)

```bash
python -m venv venv
source venv/bin/activate        # On Linux/macOS
venv\Scripts\activate           # On Windows
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Download NVD JSON Data Feeds

Visit the NIST NVD data feed portal and download JSON format feeds:

🔗 [https://nvd.nist.gov/vuln/data-feeds](https://nvd.nist.gov/vuln/data-feeds)

Place the downloaded `.json` files inside the `DataSample/` directory.

---

## Running the Tool

### Step 1 — Configure Parameters

Open the configuration section in `main.py` and set:

```python
START_YEAR = 2018
END_YEAR = 2024
KEYWORDS = ["medical device", "EHR", "DICOM", "infusion pump", "healthcare"]
```

### Step 2 — Run the Analysis

```bash
python main.py
```

### Step 3 — View Results

After execution, the `outputs/` folder will contain:

| File | Description |
|------|-------------|
| `cve_results.csv` | Filtered CVE entries with CVSS metrics |
| `cwe_summary.csv` | CWE category statistics and average scores |
| `software_products.csv` | Affected software/product frequency list |

---

## Sample Output

```
[INFO] Loading NVD JSON feeds from DataSample/...
[INFO] Parsed 14,823 CVE entries (2018-2024)
[INFO] BERT filtering: 1,247 healthcare-relevant CVEs identified
[INFO] CWE categories found: 38
[INFO] Average CVSS Base Score: 7.42
[INFO] Export complete → outputs/cve_results.csv
```

---

## Research Context

This tool was developed as part of the research paper:

> **"Security Vulnerability Analysis in Healthcare: A CVE-Based Study Using NIST NVD, BERT NLP, and CVSSv3.1"**  
> Aman Kumar, Tarun Kumar  
> Guided by: Mr. Anand Krishna (Assistant Professor, CSE)  
> SRM Institute of Science and Technology, NCR Campus — B.Tech CSE (Cyber Security), 2026

---

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## Contact

**Aman Kumar**
- GitHub: [@utkarshaman13](https://github.com/utkarshaman13)

**Tarun Kumar**
- GitHub: https://github.com/Tarun30007

---

## Acknowledgements

We gratefully acknowledge the **National Institute of Standards and Technology (NIST)** and the **National Vulnerability Database (NVD)** team for providing open-access CVE data feeds in JSON format. We also thank the open-source community behind the `transformers`, `pandas`, and related Python libraries that made this research possible.
