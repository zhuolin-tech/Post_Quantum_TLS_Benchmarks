# Post-Quantum TLS Benchmark

This repository contains a Python script that benchmarks cryptographic operations for both traditional TLS and hybrid (post-quantum) TLS schemes. The script performs several tests—such as ECDHE key generation, RSA encryption/decryption, Kyber encapsulation/decapsulation, as well as ECDSA signing and verification—and visualizes the results using bar charts.

> **Important:** Do not use Google Colab for this project. Google Colab is unsuitable for installing the required Open Quantum Safe libraries and compiling the native C components.

---

## Project Information

**Hybrid Classical-Quantum Cryptography in a Post-Quantum World**  

**Authors:**  
- Zhuolin Li, zhuolin@gatech.edu
- Tyler Jeng, skakubal3@gatech.edu
- Shruti Kakubal, tjeng7@gatech.edu
- Delaney Gomen, dgomen3@gatech.edu

This project is part of CS6262 Computer Network Security (Spring 2025) Course Project at the **Georgia Institute of Technology**.

---

## Requirements

- **Operating System:** A Unix-like system (Linux or macOS) is recommended. (Windows users need an appropriate build environment.)
- **Compiler:** A C99-compliant compiler (e.g., gcc, clang) to compile the OQS library.
- **Python:** Version 3.7 or newer.
- **Note:** *Do not use Google Colab.* You will likely run into environment limitations and dependency issues there.

---

## Installation

### System Dependencies

Before starting, install essential system packages. For example, on Ubuntu/Debian, run:

```bash
sudo apt update
sudo apt install build-essential cmake git python3-dev
```

On macOS, you can use [Homebrew](https://brew.sh):

```bash
brew install cmake git
```

### Installing the Open Quantum Safe (OQS) Library

The benchmark script depends on [liboqs](https://github.com/open-quantum-safe/liboqs) and its Python bindings ([py-oqs](https://github.com/open-quantum-safe/py-oqs)). Follow these steps to install both:

1. **Clone and Build liboqs:**

   Open a terminal and run the following commands:

   ```bash
   git clone --branch main https://github.com/open-quantum-safe/liboqs.git
   cd liboqs
   mkdir build && cd build
   cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release ..
   make -j$(nproc)
   sudo make install
   sudo ldconfig  # Refresh shared library cache (Linux only)
   ```

   *Note:* The `-j$(nproc)` flag speeds up compilation by using multiple processor cores. Adjust the flag according to your system if necessary.

2. **Install py-oqs (Python bindings):**

   First, ensure that `pip` is updated:

   ```bash
   python3 -m pip install --upgrade pip
   ```

   Then install py-oqs using pip:

   ```bash
   python3 -m pip install py-oqs
   ```

   If you encounter errors during the installation, check [py-oqs’ installation instructions](https://github.com/open-quantum-safe/py-oqs) for troubleshooting.

### Python Dependencies

Install the required Python packages using pip:

```bash
python3 -m pip install cryptography matplotlib numpy
```

Ensure that all packages are installed in your working Python environment. It is recommended to use a virtual environment:

```bash
python3 -m venv oqs-env
source oqs-env/bin/activate
python3 -m pip install cryptography matplotlib numpy py-oqs
```

---

## Usage

**Run the benchmark script:**

   Simply execute the Python script:

   ```bash
   python3 benchmark_tls.py
   ```

   The script will:
   
   - Benchmark traditional TLS operations (ECDHE handshake, RSA encryption/decryption).
   - Benchmark hybrid TLS operations (ECDHE handshake, Kyber encapsulation/decapsulation).
   - Benchmark ECDHE key generation as well as ECDSA signing and verification.
   - Produce bar charts that visualize all benchmark results.
   - Print the results to the console.

---

## Expected Results


| Algorithm      | KeyGen | Sign | Verify | Encrypt | Decrypt |
|----------------|--------|------|--------|---------|---------|
| **RSA**         | ✅     | ✅   | ✅     | ✅      | ✅      |
| **Elliptic Curve** (ECDSA/ECDHE) | ✅     | ✅   | ✅     | ❌      | ❌      |
| **Kyber**       | ✅     | ❌   | ❌     | ✅*     | ✅*     |
| **ML-DSA**      | ✅     | ✅   | ✅     | ❌      | ❌      |
| **Falcon**      | ✅     | ✅   | ✅     | ❌      | ❌      |

---

### 🔍 Notes:

- **Encrypt/Decrypt for Kyber** marked as ✅* because Kyber doesn't provide general-purpose encryption like RSA; instead, it supports *key encapsulation*, which is used to establish shared secrets over an insecure channel.
- **Elliptic Curve (ECDSA/ECDHE)** distinguishes between signing (ECDSA) and key agreement (ECDHE); it doesn't support direct encryption/decryption.
- **ML-DSA** and **Falcon** are post-quantum signature algorithms — they only support digital signing and verification, not encryption.

---



The final output of the benchmark should appear similar to the example below:

```
Running RSA Key Generation, Encryption and Decryption Benchmark...
RSA_keygen: 267712.109784 kilo cycles (±171516.243872), max: 1631687.958348, min: 41493.251076
RSA_sign: 3601.576789 kilo cycles (±1306.046234), max: 25906.042848, min: 3265.257576
RSA_verify: 143.412151 kilo cycles (±143.523298), max: 3264.315000, min: 117.686424
RSA_encrypt: 118.377329 kilo cycles (±61.617568), max: 1986.701652, min: 108.002424
RSA_decrypt: 3480.534668 kilo cycles (±619.852756), max: 7377.461652, min: 3287.046576

Running Elliptic Curve Key Generation, Signing and Verification Benchmark...
ECDHE_keygen: 63.545779 kilo cycles (±117.053063), max: 3759.409500, min: 58.239576
ECDSA_sign: 127.347034 kilo cycles (±931.274350), max: 29545.612848, min: 93.883152
ECDSA_verify: 211.547503 kilo cycles (±21.702326), max: 834.034500, min: 206.995500

Running Kyber Key Generation Benchmark...
Kyber_keygen: 83.739504 kilo cycles (±1167.428727), max: 36963.963576, min: 45.192000
Kyber_encrypt: 48.170043 kilo cycles (±9.594750), max: 214.662000, min: 45.727848
Kyber_decrypt: 38.888155 kilo cycles (±9.847678), max: 257.972076, min: 36.986424

Running ML-DSA Key Generation and Signing Benchmark...
MLDSA_keygen: 216.823030 kilo cycles (±169.970688), max: 3826.661652, min: 159.786000
MLDSA_sign: 399.151658 kilo cycles (±341.998492), max: 3747.975924, min: 143.646000
MLDSA_verify: 132.314274 kilo cycles (±62.311374), max: 786.960576, min: 108.405924

Running Falcon Key Generation and Signing Benchmark...
Falcon_keygen: 17571.517570 kilo cycles (±6885.927648), max: 117807.202848, min: 13010.186076
Falcon_sign: 504.678306 kilo cycles (±29.908109), max: 931.681500, min: 470.213076
Falcon_verify: 98.209841 kilo cycles (±10.806970), max: 212.241000, min: 93.879924

Running Traditional TLS RSA Key Exchange Benchmark...
RSA_keygen: 256561.374485 kilo cycles (±155685.866009), max: 1150148.908500, min: 37333.701924
Cert_verify: 264.464937 kilo cycles (±91.118093), max: 2020.056576, min: 223.674576
RSA_encrypt: 137.630199 kilo cycles (±99.339105), max: 3000.693924, min: 112.980000
RSA_decrypt: 3427.380173 kilo cycles (±716.401250), max: 19429.332000, min: 3271.174500
Total_time: 269971.344913 kilo cycles (±156348.887013), max: 1192956.627000, min: 50889.420000

Running Traditional TLS ECDHE RSA Key Exchange Benchmark...
ECDHE_keygen: 124.259152 kilo cycles (±41.845308), max: 635.512500, min: 68.727348
RSA_sign: 7108.792158 kilo cycles (±422.942147), max: 18848.966652, min: 6828.162576
RSA_verify: 250.329247 kilo cycles (±50.928890), max: 1222.872924, min: 226.499076
Finished_encrypt: 127.530371 kilo cycles (±25.010731), max: 687.160500, min: 113.247924
Finished_decrypt: 3361.992831 kilo cycles (±189.521092), max: 7979.483652, min: 3290.003424
Total_time: 13382.654731 kilo cycles (±870.983186), max: 31157.998848, min: 12771.310848

Running Traditional TLS ECDHE CertSign Key Exchange Benchmark...
ECDHE_keygen: 144.434219 kilo cycles (±104.839389), max: 3092.959848, min: 78.279000
CertSign_sign: 261.215335 kilo cycles (±73.665516), max: 1141.905000, min: 162.071424
CertSign_verify: 308.632873 kilo cycles (±178.024066), max: 5655.052500, min: 268.731000
Finished_encrypt: 342.892425 kilo cycles (±77.169672), max: 1001.890500, min: 220.443348
Finished_decrypt: 7231.386401 kilo cycles (±778.420190), max: 25824.000000, min: 6789.291000
Total_time: 274213.690906 kilo cycles (±160441.986174), max: 1577085.263424, min: 48083.884500

Running Hybrid TLS Kyber Key Exchange Benchmark...
ECDHE_keygen: 94.667456 kilo cycles (±74.332631), max: 2133.572424, min: 70.883652
Kyber_keygen: 68.631996 kilo cycles (±68.782869), max: 1530.072000, min: 48.552348
CertSign_sign: 186.983072 kilo cycles (±59.942478), max: 728.453076, min: 152.794152
CertSign_verify: 287.699496 kilo cycles (±55.994697), max: 1146.479076, min: 261.064500
Kyber_encapsulate: 57.896720 kilo cycles (±24.067950), max: 298.993500, min: 46.266924
Kyber_decapsulate: 41.815263 kilo cycles (±14.160780), max: 221.389152, min: 36.182652
Total_time: 3611.221317 kilo cycles (±2763.960131), max: 87041.541576, min: 3041.715348

Running Hybrid TLS Falcon Key Exchange Benchmark...
ECDHE_keygen: 87.124821 kilo cycles (±25.859646), max: 470.884500, min: 72.630000
Kyber_keygen: 63.175156 kilo cycles (±17.027075), max: 193.815576, min: 50.437500
Falcon_sign: 528.610259 kilo cycles (±65.225896), max: 2030.008500, min: 476.937000
Falcon_verify: 104.800138 kilo cycles (±17.994644), max: 355.483500, min: 95.629500
Cert_verify: 277.464812 kilo cycles (±38.219557), max: 1185.750924, min: 260.257500
Kyber_encapsulate: 57.773905 kilo cycles (±17.541707), max: 264.160152, min: 47.209500
Kyber_decapsulate: 41.990605 kilo cycles (±32.201963), max: 932.892000, min: 37.122000
Total_time: 21698.784566 kilo cycles (±4988.475413), max: 99561.068424, min: 17097.234348

Running Hybrid TLS ML-DSA Key Exchange Benchmark...
ECDHE_keygen: 78.275239 kilo cycles (±17.988498), max: 300.875424, min: 71.283924
Kyber_keygen: 54.836486 kilo cycles (±17.525464), max: 395.565576, min: 48.552348
MLDSA_keygen: 171.549300 kilo cycles (±18.445045), max: 468.731424, min: 161.400000
MLDSA_sign: 315.687786 kilo cycles (±179.422197), max: 1560.738000, min: 144.588576
MLDSA_verify: 112.378265 kilo cycles (±16.572136), max: 514.059000, min: 108.270348
Cert_verify: 264.876193 kilo cycles (±23.317289), max: 578.079924, min: 257.165076
Kyber_encapsulate: 171.549300 kilo cycles (±18.445045), max: 468.731424, min: 161.400000
Kyber_decapsulate: 38.142823 kilo cycles (±4.399474), max: 108.273576, min: 36.450576
Total_time: 4646.439574 kilo cycles (±467.906993), max: 10755.560424, min: 4264.859424

```
![image](https://github.com/user-attachments/assets/8c64ca11-34cf-4abd-9ee9-cea5cb31a670)

![image](https://github.com/user-attachments/assets/42bb7329-bc11-421c-ab1f-65205c68ba16)

![image](https://github.com/user-attachments/assets/ba8655c9-2f7b-4afc-b373-b694de5ceee7)

![image](https://github.com/user-attachments/assets/3291265d-ac7c-46cd-8ac9-bdac234a4043)

![image](https://github.com/user-attachments/assets/a49e0687-23cb-46aa-a90c-5757652562f1)

![image](https://github.com/user-attachments/assets/078a3aa3-b046-48be-9f67-adaa7020f1e6)

![image](https://github.com/user-attachments/assets/0835d5e9-e8c8-44e7-9b09-00e952bb30f2)

![image](https://github.com/user-attachments/assets/d4f23283-b37e-498d-9bc0-469bc12fafb1)


These results include:
- Average times for ECDHE handshake, RSA encryption and decryption in the traditional TLS scheme.
- Average times for Kyber encapsulation and decapsulation in the hybrid TLS scheme.
- Performance data for ECDHE key generation, and ECDSA signing/verification.
- Visualized comparisons of security bits and key sizes.

---

## Troubleshooting

- **OQS Installation Issues:**  
  Ensure that you have installed all system packages required for building C code. Check the [liboqs GitHub page](https://github.com/open-quantum-safe/liboqs) for additional dependencies and troubleshooting tips.

- **Python Binding Errors:**  
  If `py-oqs` installation fails, verify that the `liboqs` library is correctly compiled and installed and that your compiler is properly configured.

- **Do Not Use Colab:**  
  If you are working on Google Colab, many of the build tools and native library installations required for OQS are not supported. Use a local Linux or macOS machine or a suitable virtual machine instead.

- **General Environment Issues:**  
  Use Python virtual environments to avoid dependency conflicts and ensure consistent performance across tests.

