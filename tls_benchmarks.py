import time
import statistics
import matplotlib.pyplot as plt
import numpy as np

from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import hashes
import oqs  # Open Quantum Safe library for post-quantum cryptography


# ============ 1. Cryptographic Operations ============

def real_rsa_keygen():
    """
    Generate an RSA key pair with a 2048-bit modulus.
    Returns:
        public_key: RSA public key used for encryption.
        private_key: RSA private key used for decryption.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return public_key, private_key


def real_rsa_encrypt(public_key, data):
    """
    Encrypt data using the RSA public key with OAEP padding.
    Args:
        public_key: The RSA public key for encryption.
        data: The plaintext (bytes) to encrypt.
    Returns:
        ciphertext: The encrypted data.
    """
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),  # MGF1 mask generation function with SHA-256
            algorithm=hashes.SHA256(),  # Underlying hash algorithm used in OAEP
            label=None
        )
    )


def real_rsa_decrypt(private_key, ciphertext):
    """
    Decrypt data using the RSA private key with OAEP padding.
    Args:
        private_key: The RSA private key for decryption.
        ciphertext: The data to decrypt.
    Returns:
        plaintext: The decrypted data.
    """
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),  # Same settings as encryption
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def real_ecdhe_keygen():
    """
    Generate an ephemeral ECDHE key pair using the SECP256R1 elliptic curve.
    Returns:
        public_key: The ECDHE public key.
        private_key: The ECDHE private key.
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return public_key, private_key


def real_ecdhe_handshake(peer_public_key, private_key):
    """
    Simulate an ECDHE key exchange operation (handshake) by computing the shared key.
    Args:
        peer_public_key: The public key from the other party.
        private_key: The local private key.
    Returns:
        elapsed_time: The time taken (in seconds) to perform the key exchange.
    """
    start = time.perf_counter()
    _ = private_key.exchange(ec.ECDH(), peer_public_key)
    end = time.perf_counter()
    return end - start


def real_kyber_keygen():
    """
    Generate a key pair using the post-quantum key encapsulation mechanism (KEM) Kyber768.
    Returns:
        kem: The KEM object instance.
        public_key: The generated public key.
    """
    kem = oqs.KeyEncapsulation("Kyber768")
    public_key = kem.generate_keypair()
    return kem, public_key


def real_kyber_encapsulate(kem, public_key):
    """
    Perform the encapsulation operation of Kyber768 KEM to generate a ciphertext and shared secret.
    Args:
        kem: The Kyber768 KEM object instance.
        public_key: The public key used for encapsulation.
    Returns:
        elapsed_time: The time (in seconds) taken to perform encapsulation.
        ciphertext: The generated ciphertext.
    """
    start = time.perf_counter()
    ciphertext, shared_secret = kem.encap_secret(public_key)
    end = time.perf_counter()
    return end - start, ciphertext


def real_kyber_decapsulate(kem, ciphertext):
    """
    Perform the decapsulation operation of Kyber768 KEM to recover the shared secret.
    Args:
        kem: The Kyber768 KEM object instance.
        ciphertext: The ciphertext received.
    Returns:
        elapsed_time: The time (in seconds) taken to perform decapsulation.
    """
    start = time.perf_counter()
    _ = kem.decap_secret(ciphertext)
    end = time.perf_counter()
    return end - start


# ============ 2. Benchmark Functions ============

def time_to_cpu_kcycles(time):
    CPU_FREQ_HZ = 2.4e9 # WILL BE DIFFERENT FOR DIFFERENT COMPUTERS
    return (time * CPU_FREQ_HZ) / 1000 

def test_traditional_tls(rounds=10):
    """
    Test and benchmark traditional TLS operations using RSA and ECDHE.
    It benchmarks the following:
        - ECDHE handshake time
        - RSA encryption time
        - RSA decryption time
    Args:
        rounds: Number of iterations for each test.
    Returns:
        A dictionary with average times for:
            "ECDHE_handshake_avg", "RSA_encrypt_avg", "RSA_decrypt_avg"
    """
    public_key, private_key = real_rsa_keygen()
    pub_ec, priv_ec = real_ecdhe_keygen()

    # Benchmark ECDHE handshake by performing key exchange multiple times
    ecdhe_times = [
        time_to_cpu_kcycles(real_ecdhe_handshake(pub_ec, priv_ec))
        for _ in range(rounds)
        ]

    encrypt_times = []
    decrypt_times = []
    for _ in range(rounds):
        data = b"A" * 190  # Sample data of 190 bytes (adjusted to fit RSA OAEP restrictions)
        enc_start = time.perf_counter()
        ciphertext = real_rsa_encrypt(public_key, data)
        enc_end = time.perf_counter()
        encrypt_times.append(time_to_cpu_kcycles(enc_end - enc_start))

        dec_start = time.perf_counter()
        _ = real_rsa_decrypt(private_key, ciphertext)
        dec_end = time.perf_counter()
        decrypt_times.append(time_to_cpu_kcycles(dec_end - dec_start))

    return {
        "ECDHE_handshake_avg": statistics.mean(ecdhe_times),
        "RSA_encrypt_avg": statistics.mean(encrypt_times),
        "RSA_decrypt_avg": statistics.mean(decrypt_times)
    }


def test_hybrid_tls(rounds=10):
    """
    Test and benchmark a hybrid TLS approach combining ECDHE and Kyber768.
    It benchmarks the following:
        - ECDHE handshake time
        - Kyber encapsulation time
        - Kyber decapsulation time
    Args:
        rounds: Number of iterations for each test.
    Returns:
        A dictionary with average times for:
            "ECDHE_handshake_avg", "Kyber_encapsulate_avg", "Kyber_decapsulate_avg"
    """
    pub_ec, priv_ec = real_ecdhe_keygen()
    kem, public_key = real_kyber_keygen()

    ecdhe_times = []
    kem_enc_times = []
    kem_dec_times = []

    for _ in range(rounds):
        ecdhe_times.append(
            time_to_cpu_kcycles(real_ecdhe_handshake(pub_ec, priv_ec))
            )
        enc_time, ciphertext = real_kyber_encapsulate(kem, public_key)
        kem_enc_times.append(time_to_cpu_kcycles(enc_time))
        dec_time = real_kyber_decapsulate(kem, ciphertext)
        kem_dec_times.append(time_to_cpu_kcycles(dec_time))

    # Free resources associated with the KEM object
    kem.free()

    return {
        "ECDHE_handshake_avg": statistics.mean(ecdhe_times),
        "Kyber_encapsulate_avg": statistics.mean(kem_enc_times),
        "Kyber_decapsulate_avg": statistics.mean(kem_dec_times)
    }


def test_ecdhe_keygen(rounds=10):
    """
    Benchmark the key generation operation for ECDHE.
    Args:
        rounds: Number of iterations for the test.
    Returns:
        The average time (in seconds) to generate an ECDHE key pair.
    """
    times = []
    for _ in range(rounds):
        start = time.perf_counter()
        _ = real_ecdhe_keygen()
        times.append(time_to_cpu_kcycles(time.perf_counter() - start))
    return statistics.mean(times)


def test_ecdsa_sign_and_verify(rounds=10):
    """
    Benchmark the ECDSA signing and verification operations.
    Uses an ECDHE key pair generated on the SECP256R1 curve.
    Args:
        rounds: Number of iterations for the test.
    Returns:
        A tuple containing:
            - Average signing time (in seconds)
            - Average verification time (in seconds)
    """
    public_key, private_key = real_ecdhe_keygen()
    message = b"Test message for ECDSA"
    sign_times = []
    verify_times = []
    for _ in range(rounds):
        sign_start = time.perf_counter()
        signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        sign_end = time.perf_counter()
        sign_times.append(time_to_cpu_kcycles(sign_end - sign_start))

        verify_start = time.perf_counter()
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        verify_end = time.perf_counter()
        verify_times.append(time_to_cpu_kcycles(verify_end - verify_start))
    return statistics.mean(sign_times), statistics.mean(verify_times)


# ============ 3. Algorithm Information ============

# This dictionary contains estimated security parameters and key sizes for each algorithm.
algo_info = {
    "RSA 2048": {
        "bits_of_security": 112,
        "public_key_size": 256,
        "private_key_size": 1024
    },
    "ECDHE secp256r1": {
        "bits_of_security": 128,
        "public_key_size": 32,
        "private_key_size": 64
    },
    "Kyber768": {
        "bits_of_security": 192,
        "public_key_size": 1184,
        "private_key_size": 2400
    },
    "Hybrid (ECDHE+Kyber768)": {
        "bits_of_security": 256,
        "public_key_size": 1216,
        "private_key_size": 2464
    },
}


# ============ 4. Visualization Helper Function ============

def plot_bar_chart(title, labels, values, ylabel):
    """
    Generate a bar chart for benchmark results.
    Enhancements include:
        - Reduced grid lines for clarity.
        - Operation labels with corresponding numeric values displayed below the chart.
        - Printing results to the console.
    Args:
        title: Title of the bar chart.
        labels: A list of operation names.
        values: A list of average times or sizes corresponding to each operation.
        ylabel: Label for the Y-axis (e.g., "Time (seconds)" or "Size (bytes)").
    """
    # Prepare the figure canvas with a specified size
    plt.figure(figsize=(9, 5))

    # Create a color map for the bars using a subset of the viridis colormap
    colors = plt.cm.viridis(np.linspace(0.3, 0.8, len(values)))

    # Draw the bar chart with edge colors and transparency
    bars = plt.bar(labels, values, color=colors, edgecolor='black', alpha=0.85)

    # Set the title and axis labels with bold fonts
    plt.title(title, fontsize=14, fontweight='bold')
    plt.xlabel("Operations", fontsize=12, fontweight='bold')
    plt.ylabel(ylabel, fontsize=12, fontweight='bold')

    # Set the y-axis range; add extra space above the highest bar; reduce grid lines
    max_value = max(values) if values else 0
    if max_value == 0:
        max_value = 1  # Prevent error when all values are zero
    plt.ylim([0, max_value * 1.2])
    plt.grid(axis='y', linestyle='--', alpha=0.4)
    plt.locator_params(axis='y', nbins=5)

    # Add numeric labels on top of each bar
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width() / 2, height,
                 f"{height:.6f}",
                 ha='center', va='bottom',
                 fontsize=11, fontweight='bold')

    # Create a summary line with each operation and its value, and print below the chart
    summary_lines = [f"{label}: {value:.6f}" for label, value in zip(labels, values)]
    summary_text = " | ".join(summary_lines)

    # Adjust the bottom margin so that summary text is not cut off
    plt.subplots_adjust(bottom=0.25)

    # Display the summary text at the bottom center of the figure
    plt.text(0.5, 0.02, summary_text,
             ha='center', va='bottom',
             transform=plt.gcf().transFigure,
             fontsize=10, fontweight='bold')

    # Also print the summary results to the console
    print(f"\n[{title}] Results:")
    for line in summary_lines:
        print(" ", line)

    # Tight layout adjustment and show the plot
    plt.tight_layout()
    plt.show()


# ============ 5. Main Program ============

if __name__ == "__main__":
    rounds = 10  # Number of iterations for each benchmark test

    # Benchmark Traditional TLS Operations
    print("Running Traditional TLS Benchmark...")
    trad_result = test_traditional_tls(rounds)

    # Benchmark Hybrid (Post-Quantum) TLS Operations
    print("\nRunning Hybrid TLS Benchmark...")
    hybrid_result = test_hybrid_tls(rounds)

    # Benchmark ECDHE Key Generation Performance
    print("\nRunning ECDHE Key Generation Benchmark...")
    ecdhe_keygen_avg = test_ecdhe_keygen(rounds)
    print(f"ECDHE KeyGen Avg: {ecdhe_keygen_avg:.6f} cycles")

    # Benchmark ECDSA Signing and Verification Performance
    print("\nRunning ECDSA Signing and Verification Benchmark...")
    ecdsa_sign_avg, ecdsa_verify_avg = test_ecdsa_sign_and_verify(rounds)
    print(f"ECDSA Sign   Avg: {ecdsa_sign_avg:.6f} cycles")
    print(f"ECDSA Verify Avg: {ecdsa_verify_avg:.6f} cycles")

    # Print Traditional TLS benchmark results to console
    print("\nTraditional TLS Results:")
    for k, v in trad_result.items():
        print(f"  {k}: {v:.6f} cycles")

    # Print Hybrid TLS benchmark results to console
    print("\nHybrid TLS Results:")
    for k, v in hybrid_result.items():
        print(f"  {k}: {v:.6f} cycles")

    # Plot benchmark results for Traditional TLS operations
    plot_bar_chart("Traditional TLS (Average Time)",
                   ["ECDHE Handshake", "RSA Encrypt", "RSA Decrypt"],
                   [trad_result["ECDHE_handshake_avg"],
                    trad_result["RSA_encrypt_avg"],
                    trad_result["RSA_decrypt_avg"]],
                   "Average k CPU Cycles")

    # Missing Key Generation time for Kyber 
    # Plot benchmark results for Hybrid TLS operations
    plot_bar_chart("Hybrid Post-Quantum TLS (Average Time)",
                   ["ECDHE Handshake", "Kyber Encapsulate", "Kyber Decapsulate"],
                   [hybrid_result["ECDHE_handshake_avg"],
                    hybrid_result["Kyber_encapsulate_avg"],
                    hybrid_result["Kyber_decapsulate_avg"]],
                   "Average k CPU Cycles")

    # Plot benchmark results for ECDHE/ECDSA performance (Key Generation, Signing, and Verification)
    plot_bar_chart("ECDHE/ECDSA Performance",
                   ["KeyGen", "Sign", "Verify"],
                   [ecdhe_keygen_avg, ecdsa_sign_avg, ecdsa_verify_avg],
                   "Average k CPU Cycles")

    # Plot security level (in bits) for each algorithm
    algorithms = list(algo_info.keys())
    plot_bar_chart("Estimated Bits of Security", algorithms,
                   [algo_info[a]["bits_of_security"] for a in algorithms],
                   "Bits")

    # Plot public key sizes for each algorithm
    plot_bar_chart("Public Key Size Comparison", algorithms,
                   [algo_info[a]["public_key_size"] for a in algorithms],
                   "Size (bytes)")

    # Plot private key sizes for each algorithm
    plot_bar_chart("Private Key Size Comparison", algorithms,
                   [algo_info[a]["private_key_size"] for a in algorithms],
                   "Size (bytes)")
