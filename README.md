# Network Intrusion Detection System (NIDS)

A hybrid Network Intrusion Detection System combining a Rust-based packet sniffer with a Python machine-learning pipeline for anomaly detection.

This project is developed as a Final Year Project with a focus on network traffic analysis, unsupervised detection, and robust system design, rather than signature-based rules.

📌 Overview

Traditional intrusion detection systems often struggle with:

Zero-day attacks

Encrypted traffic

Evolving network behaviour

This system instead focuses on:

Statistical traffic features

Unsupervised anomaly detection

Sensitivity calibration to balance false positives and detection accuracy

The aim is not only to detect anomalies, but to understand and analyse network behaviour.

🧠 Project Focus

Packet-level network analysis

Feature extraction and aggregation

Machine learning–based anomaly detection

Robustness and repeatability of results

The project is intentionally modular to allow experimentation and evaluation.

🦀 Rust Component (Packet Sniffer)

Location: RustSniffer/

Responsibilities:

Live packet capture

TCP and UDP protocol parsing

Timestamping and metadata extraction

High-performance, low-level traffic handling

Rust is used for its memory safety, performance, and suitability for long-running network tools.

🐍 Python Component (Detection & ML)

Location: Python/

Responsibilities:

Feature engineering from captured traffic

Aggregation of packets into flows

Sensitivity calibration

Unsupervised anomaly detection

The Python layer enables flexibility in data processing and model experimentation.

⚙️ Key Concepts Implemented
Feature Aggregation

Raw packets are grouped into higher-level traffic features such as volume, timing, and protocol behaviour to reduce noise and improve detection stability.

Sensitivity Calibration

Detection thresholds are tuned to minimise false positives while maintaining detection capability.

Robustness & Repeatability

The pipeline is designed to produce consistent results across similar traffic conditions.

📊 Current Status

Packet capture implemented

Python ingestion pipeline operational

Machine-learning inference working

Data storage and logging verified

Ongoing work includes evaluation, calibration, and analysis.

📁 Repository Structure
RustSniffer/   # Rust-based packet capture
Python/        # Feature extraction and ML detection
README.md

🎓 Academic Context

This project is developed as part of a Final Year Honours Project in Software Engineering / Cybersecurity, with emphasis on:

Secure systems design

Network traffic analysis

Machine learning in security contexts
