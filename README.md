🧠 IEC 61850-9-2 Sampled Values (SV) Simulator

Developed by Sugandh Pratap

This tool is a lightweight yet powerful simulator designed to publish and decode IEC 61850-9-2 Sampled Values (SV) messages over Ethernet networks. It allows users to test, validate, and analyze SV communication used in digital substations under both normal and cyber-attack conditions.

⚙️ Key Features

SV Publisher
Generates real-time three-phase voltage and current waveforms (Va, Vb, Vc, Ia, Ib, Ic) based on user-defined parameters:

Frequency (Hz)

Samples per cycle

Voltage and current amplitude

VLAN ID, APPID, and svID

Custom source and destination MAC addresses

Configurable network interface

SV Decoder
Captures and decodes live or recorded SV frames for analysis. Displays decoded values and frame structure to study communication behavior.

Cyber-Attack Simulation
Enables insertion of false or manipulated SV packets to study false data injection, zero injection, or delay-based attacks and their impact on subscriber IEDs or controllers. Useful for validating intrusion detection or watermarking-based protection algorithms.

Real-time Visualization
Displays live voltage and current waveforms during simulation for intuitive signal monitoring.

🧩 Applications

Research and teaching in IEC 61850 digital substations

Testing of SV subscribers and IED communication

Development of cybersecurity algorithms for substation automation systems

Validation of watermarking or spectral signature-based anomaly detection methods

🖥️ Technology Stack

Language: Python

GUI Framework: PyQt / Tkinter

Networking: Scapy for Ethernet frame generation and capture

Plotting: Matplotlib

📊 Example Use Case

Simulate a 3-phase 60 Hz system with 80 samples/cycle, 10 kV line voltage, and 50 A current amplitude. Inject zero or manipulated data frames to test SV subscriber response and protection algorithms.
