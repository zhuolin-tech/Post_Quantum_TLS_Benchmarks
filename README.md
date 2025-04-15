# Post-Quantum TLS Benchmark

This repository contains a Python script that benchmarks cryptographic operations for both traditional TLS and hybrid (post-quantum) TLS schemes. The script performs several tests—such as ECDHE key generation, RSA encryption/decryption, Kyber encapsulation/decapsulation, as well as ECDSA signing and verification—and visualizes the results using bar charts.

> **Important:** Do not use Google Colab for this project. Google Colab is unsuitable for installing the required Open Quantum Safe libraries and compiling the native C components.

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

The final output of the benchmark should appear similar to the example below:

```
Running Traditional TLS Benchmark...

Running Hybrid TLS Benchmark...

Running ECDHE Key Generation Benchmark...
ECDHE KeyGen Avg: 0.000020 s

Running ECDSA Signing and Verification Benchmark...
ECDSA Sign   Avg: 0.000660 s
ECDSA Verify Avg: 0.000073 s

Traditional TLS Results:
  ECDHE_handshake_avg: 0.000130 s
  RSA_encrypt_avg: 0.000142 s
  RSA_decrypt_avg: 0.001167 s

Hybrid TLS Results:
  ECDHE_handshake_avg: 0.000060 s
  Kyber_encapsulate_avg: 0.000023 s
  Kyber_decapsulate_avg: 0.000012 s

[Traditional TLS (Average Time)] Results:
  ECDHE Handshake: 0.000130
  RSA Encrypt: 0.000142
  RSA Decrypt: 0.001167

[Hybrid Post-Quantum TLS (Average Time)] Results:
  ECDHE Handshake: 0.000060
  Kyber Encapsulate: 0.000023
  Kyber Decapsulate: 0.000012

[ECDHE/ECDSA Performance] Results:
  KeyGen: 0.000020
  Sign: 0.000660
  Verify: 0.000073

[Estimated Bits of Security] Results:
  RSA 2048: 112.000000
  ECDHE secp256r1: 128.000000
  Kyber768: 192.000000
  Hybrid (ECDHE+Kyber768): 256.000000

[Public Key Size Comparison] Results:
  RSA 2048: 256.000000
  ECDHE secp256r1: 32.000000
  Kyber768: 1184.000000
  Hybrid (ECDHE+Kyber768): 1216.000000

[Private Key Size Comparison] Results:
  RSA 2048: 1024.000000
  ECDHE secp256r1: 64.000000
  Kyber768: 2400.000000
  Hybrid (ECDHE+Kyber768): 2464.000000
```

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

---

## License

This project is licensed under the MIT License.

---
