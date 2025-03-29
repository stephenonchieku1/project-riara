# Project Riara

## Overview
**Project Riara** is a **vulnerability scanner** designed to detect security weaknesses in both **network infrastructure** and **web applications**. It leverages:
- **Django** for the backend
- **Scapy** for network scanning
- **TensorFlow** for behavior-based anomaly detection
- **OWASP ZAP** for web application security testing

---

## Key Features

### 1. Project Setup
- Organized into **backend, frontend, docs, and tests** directories.
- Uses a **virtual environment** for dependency management.
- Built on **Django** for user authentication.

### 2. User Authentication
- Implements **user registration and login** using Django’s built-in authentication.
- Supports **multi-factor authentication (MFA)** via **django-otp**.

### 3. Network Scanning (Core Engine)
- Scans **IP addresses** for **open ports (1-1024)**.
- Uses **Scapy** and Python’s **socket library** for **port scanning**.
- Logs **open ports** and attempts to **identify running services**.

### 4. Web Application Scanning
- Uses **BeautifulSoup** for **basic XSS vulnerability detection**.
- Employs **OWASP ZAP API** for **comprehensive web scanning**.

### 5. Signature-Based Detection
- Maintains a **CVE database** for **known vulnerabilities** (e.g., FTP buffer overflow, HTTP XSS).
- Matches open ports and services against the **CVE list** to identify risks.

### 6. Behavior-Based Detection (AI Integration)
- Uses **TensorFlow** and **Autoencoders** to detect **anomalous network behavior**.
- Applies **machine learning models** to classify **normal vs. suspicious activity**.

### 7. Results Processing and Prioritization
- Uses **CVSS scores** to **prioritize vulnerabilities**.
- Groups threats into **high, medium, and low risk** categories.

### 8. Deployment
- Configured for **cloud deployment** using **GitHub Actions** and **AWS EC2**.
- Automates **dependency installation, testing, and deployment**.

---

## Installation

```sh
# Clone the repository
git clone https://github.com/stephenonchieku1/project-riara.git
cd project-riara

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`

# Install dependencies
pip install -r requirements.txt

# Run the application
python manage.py runserver
```

---

## Usage
1. **Authenticate**: Register or log in using the web interface.
2. **Run Scans**:
   - **Network Scan**: Enter an IP range to check for open ports and services.
   - **Web Scan**: Provide a URL to check for vulnerabilities using OWASP ZAP.
3. **View Results**:
   - Results are categorized into **low, medium, and high-risk vulnerabilities**.
   - AI-driven **behavior analysis** highlights **anomalous activities**.

---

## Technologies Used
- **Python, Django** (Backend, Authentication)
- **Scapy** (Network Scanning)
- **OWASP ZAP API, BeautifulSoup** (Web Security Testing)
- **TensorFlow, Autoencoders** (AI-driven anomaly detection)
- **GitHub Actions, AWS EC2** (CI/CD & Deployment)

---

## Contributing
Contributions are welcome! Follow these steps:
1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Commit your changes (`git commit -m "Add new feature"`).
4. Push to the branch (`git push origin feature-branch`).
5. Open a **Pull Request**.

---

## License
This project is licensed under the **MIT License**.

---

## Contact
For inquiries, feel free to reach out:
- **Email**: ciphertech254@gmail.com
- **GitHub**: [stephenonchieku1](https://github.com/stephenonchieku1/project-riara)

