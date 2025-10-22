# ⚡ IEC 61850-9-2 Sampled Values (SV) Simulator
**Developed by [Sugandh Pratap](mailto:sugandh@iitk.ac.in)**

A Python-based simulator for **publishing and decoding IEC 61850-9-2 Sampled Values (SV)** messages used in **digital substations**.  
This tool enables testing, validation, and cybersecurity research on **Sampled Value communication** — including the simulation of **cyber-attacks** like false data injection and zero-packet injection.

---

## 🧠 Overview

The **IEC 61850-9-2 SV Simulator** provides a complete environment to:
- Generate (publish) real-time SV packets with customizable parameters.
- Decode (subscribe) and analyze SV messages on the network.
- Simulate and visualize normal and attack scenarios in **substation automation systems (SAS)**.

It’s ideal for **researchers, students, and developers** working on:
- Substation communication testing
- Cybersecurity for smart grids
- Intrusion detection and watermarking techniques

---

## 🧩 Features

### 🖥 SV Publisher
- Generates real-time **3-phase voltage and current signals** (Va, Vb, Vc, Ia, Ib, Ic)
- Fully configurable parameters:
  - Network Interface  
  - VLAN ID, APPID, svID  
  - Source & Destination MAC  
  - Frequency (Hz), Samples/Cycle  
  - Voltage and Current Amplitudes  
- Displays live waveform plots during publishing  
- Sends frames over Ethernet in **IEC 61850-9-2 format**

### 🔍 SV Decoder
- Captures SV packets from a selected interface
- Decodes and displays:
  - Ethernet, APPID, and VLAN headers  
  - svID, sample count, and dataset values  
- Useful for analyzing SV communication behavior and validating interoperability

### 🧠 Cyber-Attack Simulation
- Inject **false, zero, or manipulated SV frames**  
- Test **false data injection (FDI)** and **delay-based attacks**  
- Evaluate the impact on **IEDs, controllers**, and **Wide Area Monitoring Systems (WAMS)**  
- Supports testing of **watermarking** and **spectral signature-based anomaly detection** methods

### 📈 Real-time Visualization
- Voltage and current waveforms updated live
- Intuitive plots for quick signal monitoring and debugging

---

## 🧰 Technology Stack

| Component | Technology |
|------------|-------------|
| Language | Python |
| GUI | PyQt5 / Tkinter |
| Packet Handling | Scapy |
| Plotting | Matplotlib |
| Protocol | IEC 61850-9-2 (Sampled Values) |

---

## 🚀 Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/<yourusername>/IEC61850-9-2-SV-Simulator.git
   cd IEC61850-9-2-SV-Simulator
   ```

2. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```
   *(Typical dependencies: `scapy`, `pyqt5`, `matplotlib`, `numpy`)*

3. **Run the Application**
   ```bash
   python SV_Simulator.py
   ```

---

## ⚙️ Usage

### 1. Start SV Publisher
- Configure parameters (frequency, voltage/current amplitude, samples per cycle, etc.)
- Select the appropriate **network interface**
- Click **Start Simulation**
- Observe live waveforms of Va, Vb, Vc, Ia, Ib, Ic

### 2. Start SV Decoder
- Switch to the **SV Decoder** tab
- Select the network interface to capture from
- Click **Start Decoding** to view live SV packet data

### 3. Simulate an Attack
- Inject zero or false samples to simulate FDI attacks
- Observe changes in the waveform or in a subscribing IED
- Useful for validating detection algorithms

---

## 📷 Screenshot

**IEC 61850-9-2 SV Publisher Interface**
<img width="1202" height="831" alt="SV-attack" src="https://github.com/user-attachments/assets/8079230c-bd9c-416b-8ad9-ad103f341513" />
<img width="1004" height="723" alt="image" src="https://github.com/user-attachments/assets/56efef92-6420-41d9-93f5-4a45698025a7" />


---

## 🧪 Research Applications

This simulator has been used in ongoing research on:
- Watermarking-based cyber attack detection in SV communication  
- Spectral signature-based authentication of IEC 61850 messages  
- Security evaluation of **Digital Substations** and **Wide Area Monitoring Systems (WAMS)**  

If you use this simulator for your research, please cite the related publications or acknowledge this repository.

---

## 📜 Citation

If this simulator assists your research or project, please cite as:

> **Sugandh Pratap**, *"IEC 61850-9-2 Sampled Values Simulator for Cybersecurity and Communication Testing"*, 2025.  
> GitHub Repository: [https://github.com/<yourusername>/IEC61850-9-2-SV-Simulator](https://github.com/<yourusername>/IEC61850-9-2-SV-Simulator)

---

## 🧑‍💻 Author
**Sugandh Pratap**  
Electrical Engineer & Researcher – Power System Cybersecurity  
Email: sugandh@iitk.ac.in  
LinkedIn: https://www.linkedin.com/in/sugandhp/

---

## 📄 License
This project is released under the **MIT License**.  
You are free to use, modify, and distribute it for research and educational purposes with proper credit.
