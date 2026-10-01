# SS7
🛡️ SS7 Sentinel

A lightweight, local-only Python project for learning about SS7 security monitoring concepts through simulated telecom signalling events.

«⚠️ Educational & Defensive Project
This project does not connect to real SS7 networks, mobile operators, SIM cards, or telecom infrastructure.»

🚀 Features

- Simulated SS7 signalling events
- Detects unknown signalling sources
- Tracks repeated activity
- Generates a JSON security report
- No external dependencies
- Runs locally with Python


▶️ Usage

Run:

python ss7_sentinel.py

Generate a JSON report:

python ss7_sentinel.py --report

🔍 What It Demonstrates

The project demonstrates basic defensive concepts such as:

- Trusted vs. unknown signalling nodes
- Repeated signalling activity
- Event analysis
- Basic alert generation
- Security reporting

All events are simulated locally for educational purposes.

🔐 Safety

This project is intentionally designed for learning and defensive analysis.

It does not provide functionality for:

- Intercepting calls or SMS
- Accessing real SS7 infrastructure
- Attacking mobile networks
- Sending real signalling messages
- Denial-of-service attacks

📜 License

Released under the MIT License. See "LICENSE" for details.

👨‍💻 Author

Created as a personal cybersecurity/telecom learning project.

⭐ If you're learning telecom security too, feel free to explore the code and experiment with the simulated data.