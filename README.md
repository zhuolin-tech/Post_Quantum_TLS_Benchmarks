# TLS Performance Comparison: Traditional vs Post-Quantum Hybrid

This Python script benchmarks and visualizes the performance differences between:

- Traditional TLS (RSA + ECDHE)
- Post-quantum Hybrid TLS (Kyber768 + ECDHE)

All cryptographic operations are **real** (not simulated), using:

- [`cryptography`](https://cryptography.io/) for RSA encryption
- [`oqs-python`](https://github.com/open-quantum-safe/liboqs-python) for Kyber768 KEM

---

## 🔧 Requirements

Install dependencies (Linux/macOS):

```bash
# Install dependencies
sudo apt install cmake build-essential python3-dev

# Clone and build liboqs
git clone --recursive https://github.com/open-quantum-safe/liboqs
cd liboqs && mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=../install -DBUILD_SHARED_LIBS=ON -DOQS_DIST_BUILD=ON ..
make -j && make install

# Install oqs-python
cd ../../
git clone https://github.com/open-quantum-safe/liboqs-python
cd liboqs-python
export LIBOQS_DIR=$(pwd)/../liboqs/install
python3 -m pip install .

# Additional Python packages
pip install matplotlib cryptography numpy
