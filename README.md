Network Intrusion Detection System (NIDS)

A hybrid Network Intrusion Detection System combining a high-performance Rust packet sniffer with Python-based machine learning anomaly detection, designed as a final-year cybersecurity project.

This project focuses on real-time traffic capture, feature extraction, statistical aggregation, and ML-based intrusion detection, with an emphasis on robustness, repeatability, and explainability rather than black-box detection.

📌 Project Motivation

Traditional signature-based NIDS struggle against:

Zero-day attacks

Encrypted traffic

Evolving network behaviour

This system instead uses:

Statistical traffic features

Unsupervised anomaly detection

Sensitivity calibration to balance false positives and detection accuracy

The goal is not just detection, but understanding why traffic is flagged

🧠 System Architecture
┌──────────────┐
│ Network NIC  │
└──────┬───────┘
       │
┌──────▼────────┐
│ Rust Sniffer  │  (pcap, TCP/UDP parsing)
│  - High perf  │
│  - Low level  │
└──────┬────────┘
       │ JSON / IPC
┌──────▼──────────┐
│ Python Pipeline │
│  - Feature eng  │
│  - Aggregation  │
│  - ML detection │
└──────┬──────────┘
       │
┌──────▼──────────┐
│ Storage / Logs  │
│ (MongoDB / CSV) │
└─────────────────┘

🦀 Rust Component (Packet Sniffer)

Located in:

RustSniffer/


Responsibilities:

Live packet capture

Protocol parsing (TCP / UDP)

Timestamping & metadata extraction

Minimal processing for performance

Streaming structured data to Python

Why Rust?

Memory safety

Zero-cost abstractions

Suitable for long-running network tools

Avoids common C/C++ packet parsing vulnerabilities

🐍 Python Component (Detection & ML)

Located in:

Python/


Responsibilities:

Feature extraction

Flow aggregation

Sensitivity calibration

Unsupervised ML detection

Techniques used:

Statistical traffic features

Sliding window aggregation

Models such as:

Isolation Forest

Local Outlier Factor

One-Class SVM (model selection subject to evaluation)

⚙️ Key Concepts Implemented
1. Feature Aggregation

Raw packets are aggregated into higher-level traffic features:

Packet counts

Byte volumes

Inter-arrival times

Flow duration

Protocol distribution

This reduces noise and improves ML stability.

2. Sensitivity Calibration

Thresholds are tuned to:

Minimise false positives

Maintain detection capability

Ensure repeatable results across runs

This is critical for real-world usability.

3. Robustness & Repeatability

The system is designed to:

Produce consistent results under similar traffic

Avoid over-sensitivity to minor fluctuations

Support controlled evaluation and benchmarking

📊 Current Status

✔ Rust packet capture working
✔ Python ingestion pipeline working
✔ ML inference operational
✔ Data storage verified

🚧 In progress:

Final sensitivity calibration

Aggregation optimisation

Evaluation & metrics

Visualization layer

🧪 How to Run (High Level)

Detailed setup instructions will be added once the pipeline is finalised.

Start the Rust sniffer

Run the Python receiver / ML pipeline

Generate network traffic

Observe detections and stored results

🎓 Academic Context

This project is developed as a Final Year Honours Project in Cybersecurity / Software Engineering, with a focus on:

Secure systems design

Network traffic analysis

Machine learning in security

Real-world feasibility

📁 Repository Structure
.
├── RustSniffer/     # High-performance packet capture
├── Python/          # Feature extraction & ML detection
├── .idea/           # IDE config (can be ignored)
└── README.md

🚀 Future Work

Encrypted traffic behavioural analysis

Model comparison & benchmarking

Visualization dashboard

Alert explainability

Dataset export for academic evaluation

📜 License

This project is for academic and educational purposes.
