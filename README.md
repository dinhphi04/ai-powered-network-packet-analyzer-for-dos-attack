# AI-Powered Network Packet Analyzer for DoS Detection

## Overview
A real-time network traffic monitoring system using Machine Learning to detect DoS attacks and automatically block malicious IP addresses.

## Features
- Real-time packet capture with Scapy
- DoS detection using Random Forest
- Threshold optimization for improved accuracy
- Automatic IP blocking via iptables
- Monitoring dashboard with Streamlit

## Tech Stack
- Python (Scapy, Scikit-learn, Random Forest)

## Dataset
UNSW-NB15 dataset (not included due to large size)
https://www.unb.ca/cic/datasets/cic-unsw-nb15.html
## How to Run
```bash
pip install -r requirements.txt
python main.py
