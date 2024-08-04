# 🛡️ **WebMedic: Website Vulnerability Scanner** 🔍

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Build Status](https://img.shields.io/github/actions/workflow/status/darkstarbdx/webmedic/CI.yml)

## **Overview**

**WebMedic** is a powerful tool designed to scan websites for various vulnerabilities, including **SQL Injection**, **XSS**, **Path Traversal**, and more. It automates security checks and provides a detailed report of potential vulnerabilities.

## **Features** ✨

- **Comprehensive Scanning**: Detects a wide range of vulnerabilities such as **SQL Injection**, **XSS**, **Path Traversal**, **Directory Listing**, and more. 🔍
- **Color-Coded Results**: Get detailed, color-coded output for easy interpretation. 🌈
- **ASCII Art Banner**: Enjoy a unique ASCII art banner each time the tool starts. 🎨
- **Flexible Scanning Options**: Scan main domains, all subdomains, or everything. 🌐

## Installation

### Linux/Ubuntu

1. **Clone the repository:**
   ```bash
   git clone https://github.com/darkstarbdx/webmedic.git
   cd webmedic
   ```

2. **Install dependencies:**
   - Ensure Python 3 and pip are installed:
     ```bash
     sudo apt-get update
     sudo apt-get install python3 python3-pip
     ```

   - Install required Python packages using `requirements.txt`:
     ```bash
     pip3 install -r requirements.txt
     ```

### Termux (Android)

1. **Install Termux from the Google Play Store.**
2. **Setup Termux:**
   ```bash
   pkg update && pkg upgrade
   pkg install python git
   ```

3. **Clone the repository:**
   ```bash
   git clone https://github.com/darkstarbdx/webmedic.git
   cd webmedic
   ```

4. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## Usage

⚠️ **Warning: Ensure you have explicit permission to use this tool on any network or system. Unauthorized usage is illegal and unethical. The Creator is not responsible for any damage caused by misuse of this tool**

1. **Navigate to the directory:**
   ```bash
   cd webmedic
   ```

2. **Run the script:**
   - Linux/Ubuntu:
     ```bash
     python3 webmedic.py
     ```

   - Termux:
     ```bash
     python webmedic.py
     ```

## Notes 📌
SSL Verification Warning: The tool currently disables SSL certificate verification. For production use, ensure you handle SSL verification appropriately.🔒
Advanced Options: The tool supports scanning for a wide range of vulnerabilities. Make sure to review and understand the implications of each scan type. 🔎
Contributing 🤝
Contributions are welcome! Please read the contributing guidelines first.

## License 📜
This project is licensed under the MIT License. 📝
