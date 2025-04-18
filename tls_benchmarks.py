import time
import statistics
import matplotlib.pyplot as plt
import numpy as np

from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import hashes
import oqs  # Open Quantum Safe library for post-quantum cryptography


# ============ 1. Cryptographic Operations ============

def rsa_keygen():
    """
    Generate an RSA key pair with a 2048-bit modulus.
    Returns:
        public_key: RSA public key used for encryption.
        private_key: RSA private key used for decryption.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return public_key, private_key

def rsa_sign(private_key, data):
    """
    Sign data using the RSA private key with PSS padding.
    Args:
        private_key: The RSA private key for signing.
        data: The data to sign (bytes).
    Returns:
        signature: The signature of the data.
    """
    # Sign the data using PSS padding with SHA-256
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def rsa_verify(public_key, signature, data):
    """
    Verify the signature of data using the RSA public key with PSS padding.
    Args:
        public_key: The RSA public key for verification.
        signature: The signature to verify.
        data: The data that was signed.
    Returns:
        True if the signature is valid, False otherwise.
    """
    try:
        # Verify the signature using the same padding and hash algorithm
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        # If verification succeeds (no exception is raised), return True
        return True
    except Exception:
        # If verification fails, an exception is raised, return False
        return False

def rsa_encrypt(public_key, data):
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

def rsa_decrypt(private_key, ciphertext):
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

def ecdhe_keygen():
    """
    Generate an ephemeral ECDHE key pair using the SECP256R1 elliptic curve.
    Returns:
        public_key: The ECDHE public key.
        private_key: The ECDHE private key.
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return public_key, private_key

def ecdsa_sign(private_key, data):
    """
    Sign data using the ECDSA algorithm with SHA-256 hash.
    Args:
        private_key: The ECDSA private key for signing.
        data: The data to sign (bytes).
    Returns:
        signature: The signature of the data.
    """
    # Sign the data using ECDSA with SHA-256
    signature = private_key.sign(
        data,
        ec.ECDSA(hashes.SHA256())
    )
    return signature

def ecdsa_verify(public_key, signature, data):
    """
    Verify the ECDSA signature of data using the public key.
    Args:
        public_key: The ECDSA public key for verification.
        signature: The signature to verify.
        data: The data that was signed.
    Returns:
        True if the signature is valid, False otherwise.
    """
    try:
        # Verify the signature using ECDSA with SHA-256
        public_key.verify(
            signature,
            data,
            ec.ECDSA(hashes.SHA256())
        )
        # If verification succeeds (no exception is raised), return True
        return True
    except Exception:
        # If verification fails, an exception is raised, return False
        return False

def kyber_keygen():
    """
    Generate a key pair using the post-quantum key encapsulation mechanism (KEM) Kyber768.
    Returns:
        kem: The KEM object instance.
        public_key: The generated public key.
    """
    kem = oqs.KeyEncapsulation("Kyber768")
    public_key = kem.generate_keypair()
    return kem, public_key

def kyber_encapsulate(kem, public_key):
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


def kyber_decapsulate(kem, ciphertext):
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


def mldsa_keygen():
    """
    Generate a key pair using the ML-DSA (CRYSTALS-Dilithium) post-quantum signature algorithm.
    Returns:
        private_key: The ML-DSA signature object instance.
        public_key: The ML-DSA public key used for verification.
    """
    # Create a Dilithium signature object
    private_key = oqs.Signature("Dilithium3")
    # Generate the keypair - public key is returned, private key is stored in sig object
    public_key = private_key.generate_keypair()
    return private_key, public_key


def mldsa_sign(private_key, data):
    """
    Sign data using the ML-DSA (CRYSTALS-Dilithium) algorithm.
    Args:
        private_key: The ML-DSA signature object instance (contains private key).
        data: The data to sign (bytes).
    Returns:
        signature: The signature of the data.
    """
    # Sign the data using ML-DSA
    signature = private_key.sign(data)
    return signature


def mldsa_verify(private_key, public_key, signature, data):
    """
    Verify the ML-DSA signature of data using the public key.
    Args:
        private_key: The ML-DSA signature object instance.
        public_key: The ML-DSA public key for verification.
        signature: The signature to verify.
        data: The data that was signed.
    Returns:
        True if the signature is valid, False otherwise.
    """
    try:
        # Verify the signature using ML-DSA
        result = private_key.verify(data, signature, public_key)
        return result
    except Exception:
        # If verification fails, an exception is raised, return False
        return False

def falcon_keygen():
    """
    Generate a key pair using the Falcon post-quantum signature algorithm.
    Returns:
        private_key: The Falcon signature object instance.
        public_key: The Falcon public key used for verification.
    """
    # Create a Falcon signature object
    private_key = oqs.Signature("Falcon-512")
    # Generate the keypair - public key is returned, private key is stored in sig object
    public_key = private_key.generate_keypair()
    return private_key, public_key


def falcon_sign(private_key, data):
    """
    Sign data using the Falcon algorithm.
    Args:
        private_key: The Falcon signature object instance (contains private key).
        data: The data to sign (bytes).
    Returns:
        signature: The signature of the data.
    """
    # Sign the data using Falcon
    signature = private_key.sign(data)
    return signature


def falcon_verify(private_key, public_key, signature, data):
    """
    Verify the Falcon signature of data using the public key.
    Args:
        private_key: The Falcon signature object instance.
        public_key: The Falcon public key for verification.
        signature: The signature to verify.
        data: The data that was signed.
    Returns:
        True if the signature is valid, False otherwise.
    """
    try:
        # Verify the signature using Falcon
        result = private_key.verify(data, signature, public_key)
        return result
    except Exception:
        # If verification fails, an exception is raised, return False
        return False

# ============ 2. Benchmark Functions ============

def time_to_cpu_kcycles(time):
    CPU_FREQ_HZ = 2.4e9 # WILL BE DIFFERENT FOR DIFFERENT COMPUTERS
    return (time * CPU_FREQ_HZ) / 1000

def test_traditional_tls_rsa_kex():
    """
    Test and benchmark TLS 1.2 handshake using pure RSA key‑exchange.
    It benchmarks the following:
        - RSA keypair generation time (KeyGen)
        - Certificate chain signature verification time (Verify)
        - RSA encryption of the pre‑master secret (Encrypt)
        - RSA decryption of the pre‑master secret (Decrypt)
    Returns:
        A dict with average times for:
            "RSA_keygen_avg",
            "Cert_verify_avg",
            "RSA_encrypt_avg",
            "RSA_decrypt_avg"
    """
    # Measure RSA key generation time
    start = time.perf_counter()
    public_key, private_key = rsa_keygen()
    keygen_time = time_to_cpu_kcycles(time.perf_counter() - start)
    
    # Simulate certificate verification (using RSA verify as proxy)
    cert_data = b"TLS Certificate Chain Data"
    # Generate a signature for the certificate data
    cert_signature = rsa_sign(private_key, cert_data)
    
    start = time.perf_counter()
    _ = rsa_verify(public_key, cert_signature, cert_data)
    cert_verify_time = time_to_cpu_kcycles(time.perf_counter() - start)
    
    # Measure RSA encryption of pre-master secret
    pre_master_secret = b"A" * 190  # Simulated pre-master secret
    
    start = time.perf_counter()
    ciphertext = rsa_encrypt(public_key, pre_master_secret)
    encrypt_time = time_to_cpu_kcycles(time.perf_counter() - start)
    
    # Measure RSA decryption of pre-master secret
    start = time.perf_counter()
    _ = rsa_decrypt(private_key, ciphertext)
    decrypt_time = time_to_cpu_kcycles(time.perf_counter() - start)

    return {
        "RSA_keygen_avg": keygen_time,
        "Cert_verify_avg": cert_verify_time,
        "RSA_encrypt_avg": encrypt_time,
        "RSA_decrypt_avg": decrypt_time
    }


def test_traditional_tls_ecdhe_rsa():
    """
    Test and benchmark TLS 1.2 ECDHE_RSA handshake.
    It benchmarks the following:
        - ECDHE ephemeral keypair generation time (KeyGen)
        - RSA signing of the ServerKeyShare (Sign)
        - RSA verification of ServerKeyShare and certificate chain (Verify)
        - symmetric encryption of Finished message (Encrypt)
        - symmetric decryption of Finished message (Decrypt)
    Returns:
        A dict with average times for:
            "ECDHE_keygen_avg",
            "RSA_sign_avg",
            "RSA_verify_avg",
            "Finished_encrypt_avg",       
            "Finished_decrypt_avg"        
    """
    # Generate RSA keys for certificate operations
    rsa_pub_key, rsa_priv_key = rsa_keygen()
    
    # Measure ECDHE key generation time
    start = time.perf_counter()
    ec_pub_key, ec_priv_key = ecdhe_keygen()
    ecdhe_keygen_time = time_to_cpu_kcycles(time.perf_counter() - start)
    
    # Simulate ServerKeyShare data
    server_key_share = b"ECDHE Server Key Share Data"
    
    # Measure RSA signing time for ServerKeyShare
    start = time.perf_counter()
    signature = rsa_sign(rsa_priv_key, server_key_share)
    rsa_sign_time = time_to_cpu_kcycles(time.perf_counter() - start)
    
    # Measure RSA verification time
    start = time.perf_counter()
    _ = rsa_verify(rsa_pub_key, signature, server_key_share)
    rsa_verify_time = time_to_cpu_kcycles(time.perf_counter() - start)
    
    # Simulate symmetric encryption/decryption using RSA as a proxy
    # (In real TLS, this would use AES or another symmetric cipher)
    finished_message = b"TLS Finished Message"
    
    # Encrypt using RSA as a proxy for symmetric encryption
    start = time.perf_counter()
    ciphertext = rsa_encrypt(rsa_pub_key, finished_message[:190])  # Truncate to fit RSA
    encrypt_time = time_to_cpu_kcycles(time.perf_counter() - start)
    
    # Decrypt using RSA as a proxy for symmetric decryption
    start = time.perf_counter()
    _ = rsa_decrypt(rsa_priv_key, ciphertext)
    decrypt_time = time_to_cpu_kcycles(time.perf_counter() - start)
    
    return {
        "ECDHE_keygen_avg": ecdhe_keygen_time,
        "RSA_sign_avg": rsa_sign_time,
        "RSA_verify_avg": rsa_verify_time,
        "Finished_encrypt_avg": encrypt_time,
        "Finished_decrypt_avg": decrypt_time
    }


def test_traditional_tls_ecdhe_certsign():
    """
    Test and benchmark TLS 1.3 handshake with ECDHE + certificate‑based signature.
    It benchmarks the following:
        - ECDHE ephemeral keypair generation time (KeyGen)
        - Certificate signature (e.g., ECDSA) over handshake transcripts (Sign)
        - Verification of the certificate chain and handshake signature (Verify)
        - symmetric encryption of Finished/0-RTT messages (Encrypt)
        - symmetric decryption of Finished/0-RTT messages (Decrypt)
    Returns:
        A dict with average times for:
            "ECDHE_keygen_avg",
            "CertSign_sign_avg",
            "CertSign_verify_avg",
            "Finished_encrypt_avg",       
            "Finished_decrypt_avg"        
    """
    # Measure ECDHE key generation time
    start = time.perf_counter()
    ec_pub_key, ec_priv_key = ecdhe_keygen()
    ecdhe_keygen_time = time_to_cpu_kcycles(time.perf_counter() - start)
    
    # Simulate handshake transcript data
    handshake_transcript = b"TLS 1.3 Handshake Transcript Data"
    
    # Measure ECDSA signing time for certificate
    start = time.perf_counter()
    signature = ecdsa_sign(ec_priv_key, handshake_transcript)
    cert_sign_time = time_to_cpu_kcycles(time.perf_counter() - start)
    
    # Measure ECDSA verification time
    start = time.perf_counter()
    _ = ecdsa_verify(ec_pub_key, signature, handshake_transcript)
    cert_verify_time = time_to_cpu_kcycles(time.perf_counter() - start)
    
    # Generate RSA keys to simulate symmetric encryption (as a proxy)
    rsa_pub_key, rsa_priv_key = rsa_keygen()
    
    # Simulate Finished/0-RTT message
    finished_message = b"TLS 1.3 Finished Message"
    
    # Encrypt using RSA as a proxy for symmetric encryption
    start = time.perf_counter()
    ciphertext = rsa_encrypt(rsa_pub_key, finished_message[:190])  # Truncate to fit RSA
    encrypt_time = time_to_cpu_kcycles(time.perf_counter() - start)
    
    # Decrypt using RSA as a proxy for symmetric decryption
    start = time.perf_counter()
    _ = rsa_decrypt(rsa_priv_key, ciphertext)
    decrypt_time = time_to_cpu_kcycles(time.perf_counter() - start)
    
    return {
        "ECDHE_keygen_avg": ecdhe_keygen_time,
        "CertSign_sign_avg": cert_sign_time,
        "CertSign_verify_avg": cert_verify_time,
        "Finished_encrypt_avg": encrypt_time,
        "Finished_decrypt_avg": decrypt_time
    }


def test_hybrid_tls_kyber():
    """
    Test and benchmark a hybrid TLS handshake combining ECDHE and Kyber KEM.
    It benchmarks the following:
        - ECDHE ephemeral keypair generation time (KeyGen)
        - Kyber keypair generation time (KeyGen)
        - Certificate signature/authentication time (Sign)
        - Verification of the certificate chain and signature (Verify)
        - Kyber encapsulation time (Encapsulate)
        - Kyber decapsulation time (Decapsulate)
    Returns:
        A dict with average times for:
            "ECDHE_keygen_avg",
            "Kyber_keygen_avg",
            "CertSign_sign_avg",
            "CertSign_verify_avg",
            "Kyber_encapsulate_avg",
            "Kyber_decapsulate_avg"
    """
    # Measure ECDHE key generation time
    start = time.perf_counter()
    ec_pub_key, ec_priv_key = ecdhe_keygen()
    ecdhe_keygen_time = time_to_cpu_kcycles(time.perf_counter() - start)
    
    # Measure Kyber key generation time
    start = time.perf_counter()
    kem, kyber_pub_key = kyber_keygen()
    kyber_keygen_time = time_to_cpu_kcycles(time.perf_counter() - start)
    
    # Simulate handshake transcript data
    handshake_transcript = b"Hybrid TLS Handshake Transcript Data"
    
    # Measure ECDSA signing time for certificate
    start = time.perf_counter()
    signature = ecdsa_sign(ec_priv_key, handshake_transcript)
    cert_sign_time = time_to_cpu_kcycles(time.perf_counter() - start)
    
    # Measure ECDSA verification time
    start = time.perf_counter()
    _ = ecdsa_verify(ec_pub_key, signature, handshake_transcript)
    cert_verify_time = time_to_cpu_kcycles(time.perf_counter() - start)
    
    # Measure Kyber encapsulation time
    encap_time, ciphertext = kyber_encapsulate(kem, kyber_pub_key)
    kyber_encap_time = time_to_cpu_kcycles(encap_time)
    
    # Measure Kyber decapsulation time
    decap_time = kyber_decapsulate(kem, ciphertext)
    kyber_decap_time = time_to_cpu_kcycles(decap_time)
    
    # Free Kyber resources
    kem.free()
    
    return {
        "ECDHE_keygen_avg": ecdhe_keygen_time,
        "Kyber_keygen_avg": kyber_keygen_time,
        "CertSign_sign_avg": cert_sign_time,
        "CertSign_verify_avg": cert_verify_time,
        "Kyber_encapsulate_avg": kyber_encap_time,
        "Kyber_decapsulate_avg": kyber_decap_time
    }


def test_hybrid_tls_falcon():
    """
    Test and benchmark a hybrid TLS handshake with ECDHE+Kyber KEM and Falcon post‑quantum signatures.
    It benchmarks the following:
        - ECDHE ephemeral keypair generation time (KeyGen)
        - Kyber keypair generation time (KeyGen)
        - Falcon‑512 signature generation time on handshake data (Sign)
        - Falcon‑512 signature verification time (Verify)
        - Verification of the certificate chain (still using classic certs) (Verify)
        - Kyber encapsulation time (Encapsulate)
        - Kyber decapsulation time (Decapsulate)
    Returns:
        A dict with average times for:
            "ECDHE_keygen_avg",
            "Kyber_keygen_avg",
            "Falcon_sign_avg",
            "Falcon_verify_avg",
            "Cert_verify_avg",
            "Kyber_encapsulate_avg",
            "Kyber_decapsulate_avg"
    """
    # Measure ECDHE key generation time
    start = time.perf_counter()
    ec_pub_key, ec_priv_key = ecdhe_keygen()
    ecdhe_keygen_time = time_to_cpu_kcycles(time.perf_counter() - start)
    
    # Measure Kyber key generation time
    start = time.perf_counter()
    kem, kyber_pub_key = kyber_keygen()
    kyber_keygen_time = time_to_cpu_kcycles(time.perf_counter() - start)
    
    # Generate Falcon keys
    falcon_priv_key, falcon_pub_key = falcon_keygen()
    
    # Simulate handshake transcript data
    handshake_transcript = b"Hybrid TLS with Falcon Handshake Transcript Data"
    
    # Measure Falcon signing time
    start = time.perf_counter()
    signature = falcon_sign(falcon_priv_key, handshake_transcript)
    falcon_sign_time = time_to_cpu_kcycles(time.perf_counter() - start)
    
    # Measure Falcon verification time
    start = time.perf_counter()
    _ = falcon_verify(falcon_priv_key, falcon_pub_key, signature, handshake_transcript)
    falcon_verify_time = time_to_cpu_kcycles(time.perf_counter() - start)
    
    # Simulate certificate verification (using ECDSA as proxy for classic certs)
    cert_data = b"TLS Certificate Chain Data"
    cert_signature = ecdsa_sign(ec_priv_key, cert_data)
    
    start = time.perf_counter()
    _ = ecdsa_verify(ec_pub_key, cert_signature, cert_data)
    cert_verify_time = time_to_cpu_kcycles(time.perf_counter() - start)
    
    # Measure Kyber encapsulation time
    encap_time, ciphertext = kyber_encapsulate(kem, kyber_pub_key)
    kyber_encap_time = time_to_cpu_kcycles(encap_time)
    
    # Measure Kyber decapsulation time
    decap_time = kyber_decapsulate(kem, ciphertext)
    kyber_decap_time = time_to_cpu_kcycles(decap_time)
    
    # Free resources
    kem.free()
    falcon_priv_key.free()
    
    return {
        "ECDHE_keygen_avg": ecdhe_keygen_time,
        "Kyber_keygen_avg": kyber_keygen_time,
        "Falcon_sign_avg": falcon_sign_time,
        "Falcon_verify_avg": falcon_verify_time,
        "Cert_verify_avg": cert_verify_time,
        "Kyber_encapsulate_avg": kyber_encap_time,
        "Kyber_decapsulate_avg": kyber_decap_time
    }


def test_hybrid_tls_mldsa():
    """
    Test and benchmark a hybrid TLS handshake with ECDHE+Kyber KEM and ML‑DSA (Dilithium3) post‑quantum signatures.
    It benchmarks the following:
        - ECDHE ephemeral keypair generation time (KeyGen)
        - Kyber keypair generation time (KeyGen)
        - ML‑DSA (Dilithium3) key generation time (KeyGen) if measured separately
        - ML‑DSA signature generation time on handshake data (Sign)
        - ML‑DSA signature verification time (Verify)
        - Verification of the certificate chain (classic certs) (Verify)
        - Kyber encapsulation time (Encapsulate)
        - Kyber decapsulation time (Decapsulate)
    Returns:
        A dict with average times for:
            "ECDHE_keygen_avg",
            "Kyber_keygen_avg",
            "MLDSA_keygen_avg",   
            "MLDSA_sign_avg",
            "MLDSA_verify_avg",
            "Cert_verify_avg",
            "Kyber_encapsulate_avg",
            "Kyber_decapsulate_avg"
    """
    # Measure ECDHE key generation time
    start = time.perf_counter()
    ec_pub_key, ec_priv_key = ecdhe_keygen()
    ecdhe_keygen_time = time_to_cpu_kcycles(time.perf_counter() - start)
    
    # Measure Kyber key generation time
    start = time.perf_counter()
    kem, kyber_pub_key = kyber_keygen()
    kyber_keygen_time = time_to_cpu_kcycles(time.perf_counter() - start)
    
    # Measure ML-DSA key generation time
    start = time.perf_counter()
    mldsa_priv_key, mldsa_pub_key = mldsa_keygen()
    mldsa_keygen_time = time_to_cpu_kcycles(time.perf_counter() - start)
    
    # Simulate handshake transcript data
    handshake_transcript = b"Hybrid TLS with ML-DSA Handshake Transcript Data"
    
    # Measure ML-DSA signing time
    start = time.perf_counter()
    signature = mldsa_sign(mldsa_priv_key, handshake_transcript)
    mldsa_sign_time = time_to_cpu_kcycles(time.perf_counter() - start)
    
    # Measure ML-DSA verification time
    start = time.perf_counter()
    _ = mldsa_verify(mldsa_priv_key, mldsa_pub_key, signature, handshake_transcript)
    mldsa_verify_time = time_to_cpu_kcycles(time.perf_counter() - start)
    
    # Simulate certificate verification (using ECDSA as proxy for classic certs)
    cert_data = b"TLS Certificate Chain Data"
    cert_signature = ecdsa_sign(ec_priv_key, cert_data)
    
    start = time.perf_counter()
    _ = ecdsa_verify(ec_pub_key, cert_signature, cert_data)
    cert_verify_time = time_to_cpu_kcycles(time.perf_counter() - start)
    
    # Measure Kyber encapsulation time
    encap_time, ciphertext = kyber_encapsulate(kem, kyber_pub_key)
    kyber_encap_time = time_to_cpu_kcycles(encap_time)
    
    # Measure Kyber decapsulation time
    decap_time = kyber_decapsulate(kem, ciphertext)
    kyber_decap_time = time_to_cpu_kcycles(decap_time)
    
    # Free resources
    kem.free()
    mldsa_priv_key.free()
    
    return {
        "ECDHE_keygen_avg": ecdhe_keygen_time,
        "Kyber_keygen_avg": kyber_keygen_time,
        "MLDSA_keygen_avg": mldsa_keygen_time,
        "MLDSA_sign_avg": mldsa_sign_time,
        "MLDSA_verify_avg": mldsa_verify_time,
        "Cert_verify_avg": cert_verify_time,
        "Kyber_encapsulate_avg": kyber_encap_time,
        "Kyber_decapsulate_avg": kyber_decap_time
    }



def test_rsa_keygen(rounds=10):
    """
    Benchmarks RSA key generation operations.
    Args:
        rounds: Number of iterations of the test.
    Returns:
        Average time (in CPU cycles) to generate an RSA key pair.
    """
    times = []
    for _ in range(rounds):
        start = time.perf_counter()
        _ = rsa_keygen()
        times.append(time_to_cpu_kcycles(time.perf_counter() - start))
    return statistics.mean(times)


def test_rsa_sign_and_verify(rounds=10):
    """
    Benchmarks RSA signing and verification operations.
    Uses 2048-bit RSA keys.
    Args:
        rounds: Number of iterations of the test.
    Returns:
        A tuple containing:
            - Average signing time (in CPU cycles)
            - Average verification time (in CPU cycles)
    """
    public_key, private_key = rsa_keygen()
    message = b"Test message for RSA"
    sign_times = []
    verify_times = []
    
    for _ in range(rounds):
        # Measuring the time of signing operations using rsa_sign function
        sign_start = time.perf_counter()
        signature = rsa_sign(private_key, message)
        sign_end = time.perf_counter()
        sign_times.append(time_to_cpu_kcycles(sign_end - sign_start))
        
        # Measuring the time of a verification operation using rsa_verify function
        verify_start = time.perf_counter()
        _ = rsa_verify(public_key, signature, message)
        verify_end = time.perf_counter()
        verify_times.append(time_to_cpu_kcycles(verify_end - verify_start))
    
    return statistics.mean(sign_times), statistics.mean(verify_times)


def test_rsa_encrypt_and_decrypt(rounds=10):
    """
    Benchmarks RSA encryption and decryption operations.
    Uses 2048-bit RSA keys.
    Args:
        rounds: Number of iterations to test.
    Returns:
        Tuple containing:
            - Average encryption time (in CPU cycles)
            - Average decryption time (in CPU cycles)
    """
    public_key, private_key = rsa_keygen()
    data = b"A" * 190  # Sample data, 190 bytes (adjusted to fit RSA OAEP limits)
    encrypt_times = []
    decrypt_times = []
    
    for _ in range(rounds):
        # Measuring the time of cryptographic operations
        encrypt_start = time.perf_counter()
        ciphertext = rsa_encrypt(public_key, data)
        encrypt_end = time.perf_counter()
        encrypt_times.append(time_to_cpu_kcycles(encrypt_end - encrypt_start))
        
        # Measuring the time of decryption operations
        decrypt_start = time.perf_counter()
        _ = rsa_decrypt(private_key, ciphertext)
        decrypt_end = time.perf_counter()
        decrypt_times.append(time_to_cpu_kcycles(decrypt_end - decrypt_start))
    
    return statistics.mean(encrypt_times), statistics.mean(decrypt_times)


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
        _ = ecdhe_keygen()
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
    public_key, private_key = ecdhe_keygen()
    message = b"Test message for ECDSA"
    sign_times = []
    verify_times = []
    for _ in range(rounds):
        # Measuring the time of signing operations using ecdsa_sign function
        sign_start = time.perf_counter()
        signature = ecdsa_sign(private_key, message)
        sign_end = time.perf_counter()
        sign_times.append(time_to_cpu_kcycles(sign_end - sign_start))

        # Measuring the time of verification operations using ecdsa_verify function
        verify_start = time.perf_counter()
        _ = ecdsa_verify(public_key, signature, message)
        verify_end = time.perf_counter()
        verify_times.append(time_to_cpu_kcycles(verify_end - verify_start))
    return statistics.mean(sign_times), statistics.mean(verify_times)


def test_kyber_keygen(rounds=10):
    """
    Benchmark the key generation operation for Kyber768.
    Args:
        rounds: Number of iterations for the test.
    Returns:
        The average time (in seconds) to generate a Kyber768 key pair.
    """
    times = []
    for _ in range(rounds):
        start = time.perf_counter()
        kem, _ = kyber_keygen()
        times.append(time_to_cpu_kcycles(time.perf_counter() - start))
        # Release resources
        kem.free()
    return statistics.mean(times)

def test_kyber_encapsulate_and_decapsulate(rounds=10):
    """
    Benchmark the encapsulation and decapsulation operations for Kyber768.
    Args:
        rounds: Number of iterations for the test.
    Returns:
        A tuple containing:
            - Average encapsulation time (in CPU cycles)
            - Average decapsulation time (in CPU cycles)
    """
    kem, public_key = kyber_keygen()
    encap_times = []
    decap_times = []
    
    for _ in range(rounds):
        # Measure encapsulation time
        encap_start = time.perf_counter()
        enc_time, ciphertext = kyber_encapsulate(kem, public_key)
        encap_end = time.perf_counter()
        encap_times.append(time_to_cpu_kcycles(encap_end - encap_start))
        
        # Measure decapsulation time
        decap_start = time.perf_counter()
        _ = kyber_decapsulate(kem, ciphertext)
        decap_end = time.perf_counter()
        decap_times.append(time_to_cpu_kcycles(decap_end - decap_start))
    
    # Free resources associated with the KEM object
    kem.free()
    
    return statistics.mean(encap_times), statistics.mean(decap_times)

def test_mldsa_keygen(rounds=10):
    """
    Benchmark the key generation operation for ML-DSA (CRYSTALS-Dilithium).
    Args:
        rounds: Number of iterations for the test.
    Returns:
        The average time (in seconds) to generate a ML-DSA key pair.
    """
    times = []
    for _ in range(rounds):
        start = time.perf_counter()
        private_key, _ = mldsa_keygen()
        times.append(time_to_cpu_kcycles(time.perf_counter() - start))
        # Release resources
        private_key.free()
    return statistics.mean(times)

def test_mldsa_sign_and_verify(rounds=10):
    """
    Benchmark the ML-DSA signing and verification operations.
    Args:
        rounds: Number of iterations for the test.
    Returns:
        A tuple containing:
            - Average signing time (in seconds)
            - Average verification time (in seconds)
    """
    private_key, public_key = mldsa_keygen()
    message = b"Test message for ML-DSA"
    sign_times = []
    verify_times = []
    
    for _ in range(rounds):
        # Measuring the time of signing operations
        sign_start = time.perf_counter()
        signature = mldsa_sign(private_key, message)
        sign_end = time.perf_counter()
        sign_times.append(time_to_cpu_kcycles(sign_end - sign_start))
        
        # Measuring the time of verification operations
        verify_start = time.perf_counter()
        _ = mldsa_verify(private_key, public_key, signature, message)
        verify_end = time.perf_counter()
        verify_times.append(time_to_cpu_kcycles(verify_end - verify_start))
    
    # Free resources
    private_key.free()
    
    return statistics.mean(sign_times), statistics.mean(verify_times)

def test_falcon_keygen(rounds=10):
    """
    Benchmark the key generation operation for Falcon.
    Args:
        rounds: Number of iterations for the test.
    Returns:
        The average time (in seconds) to generate a Falcon key pair.
    """
    times = []
    for _ in range(rounds):
        start = time.perf_counter()
        private_key, _ = falcon_keygen()
        times.append(time_to_cpu_kcycles(time.perf_counter() - start))
        # Release resources
        private_key.free()
    return statistics.mean(times)

def test_falcon_sign_and_verify(rounds=10):
    """
    Benchmark the Falcon signing and verification operations.
    Args:
        rounds: Number of iterations for the test.
    Returns:
        A tuple containing:
            - Average signing time (in seconds)
            - Average verification time (in seconds)
    """
    private_key, public_key = falcon_keygen()
    message = b"Test message for Falcon"
    sign_times = []
    verify_times = []
    
    for _ in range(rounds):
        # Measuring the time of signing operations
        sign_start = time.perf_counter()
        signature = falcon_sign(private_key, message)
        sign_end = time.perf_counter()
        sign_times.append(time_to_cpu_kcycles(sign_end - sign_start))
        
        # Measuring the time of verification operations
        verify_start = time.perf_counter()
        _ = falcon_verify(private_key, public_key, signature, message)
        verify_end = time.perf_counter()
        verify_times.append(time_to_cpu_kcycles(verify_end - verify_start))
    
    # Free resources
    private_key.free()
    
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


# ============ 5. Main Program ============

if __name__ == "__main__":
    rounds = 10  # Number of iterations for each benchmark test


    # Benchmark RSA Algorithm Performance
    print("\nRunning RSA Key Generation, Encryption and Decryption Benchmark")
    rsa_keygen_avg = test_rsa_keygen(rounds)
    rsa_sign_avg, rsa_verify_avg = test_rsa_sign_and_verify(rounds)
    rsa_encrypt_avg, rsa_decrypt_avg = test_rsa_encrypt_and_decrypt(rounds)
    print(f"RSA KeyGen Avg: {rsa_keygen_avg:.6f} cycles")
    print(f"RSA Sign   Avg: {rsa_sign_avg:.6f} cycles")
    print(f"RSA Verify Avg: {rsa_verify_avg:.6f} cycles")
    print(f"RSA Encrypt Avg: {rsa_encrypt_avg:.6f} cycles")
    print(f"RSA Decrypt Avg: {rsa_decrypt_avg:.6f} cycles")


    # Benchmark Elliptic Curve Algorithm Performance
    print("\nRunning Elliptic Curve Key Generation, Signing and Verification Benchmark")
    ecdhe_keygen_avg = test_ecdhe_keygen(rounds)
    ecdsa_sign_avg, ecdsa_verify_avg = test_ecdsa_sign_and_verify(rounds)
    print(f"ECDHE KeyGen Avg: {ecdhe_keygen_avg:.6f} cycles")
    print(f"ECDSA Sign   Avg: {ecdsa_sign_avg:.6f} cycles")
    print(f"ECDSA Verify Avg: {ecdsa_verify_avg:.6f} cycles")

    # Benchmark Kyber Algorithm Performance
    print("\nRunning Kyber Key Generation Benchmark...")
    kyber_keygen_avg = test_kyber_keygen(rounds)
    kyber_encrypt_avg, kyber_decrypt_avg = test_kyber_encapsulate_and_decapsulate(rounds)
    print(f"Kyber KeyGen Avg: {kyber_keygen_avg:.6f} cycles")
    print(f"Kyber Encrypt Avg: {kyber_encrypt_avg:.6f} cycles")
    print(f"Kyber Decrypt Avg: {kyber_decrypt_avg:.6f} cycles")

    # Benchmark ML-DSA Algorithm Performance
    print("\nRunning ML-DSA Key Generation and Signing Benchmark...")
    mldsa_keygen_avg = test_mldsa_keygen(rounds)
    mldsa_sign_avg, mldsa_verify_avg = test_mldsa_sign_and_verify(rounds)
    print(f"ML-DSA KeyGen Avg: {mldsa_keygen_avg:.6f} cycles")
    print(f"ML-DSA Sign   Avg: {mldsa_sign_avg:.6f} cycles")
    print(f"ML-DSA Verify Avg: {mldsa_verify_avg:.6f} cycles")

    # Benchmark Falcon Algorithm Performance
    print("\nRunning Falcon Key Generation and Signing Benchmark...")
    falcon_keygen_avg = test_falcon_keygen(rounds)
    falcon_sign_avg, falcon_verify_avg = test_falcon_sign_and_verify(rounds)
    print(f"Falcon KeyGen Avg: {falcon_keygen_avg:.6f} cycles")
    print(f"Falcon Sign   Avg: {falcon_sign_avg:.6f} cycles")
    print(f"Falcon Verify Avg: {falcon_verify_avg:.6f} cycles")





    # Benchmark test_traditional_tls_rsa_kex
    print("\nRunning test_traditional_tls_rsa_kex Benchmark...")
    trad_rsa_kex_result = test_traditional_tls_rsa_kex()
    print("Traditional TLS RSA Key Exchange Results:")
    for k, v in trad_rsa_kex_result.items():
        print(f"  {k}: {v:.6f} cycles")

    # Benchmark test_traditional_tls_ecdhe_rsa
    print("\nRunning test_traditional_tls_ecdhe_rsa Benchmark...")
    trad_ecdhe_rsa_result = test_traditional_tls_ecdhe_rsa()
    print("Traditional TLS ECDHE RSA Key Exchange Results:")
    for k, v in trad_ecdhe_rsa_result.items():
        print(f"  {k}: {v:.6f} cycles")

    # Benchmark test_traditional_tls_ecdhe_certsign
    print("\nRunning test_traditional_tls_ecdhe_certsign Benchmark...")
    trad_ecdhe_certsign_result = test_traditional_tls_ecdhe_certsign()
    print("Traditional TLS ECDHE CertSign Results:")
    for k, v in trad_ecdhe_certsign_result.items():
        print(f"  {k}: {v:.6f} cycles")
    
    # Benchmark test_hybrid_tls_kyber
    print("\nRunning test_hybrid_tls_kyber Benchmark...")
    hybrid_kyber_result = test_hybrid_tls_kyber()
    print("Hybrid TLS Kyber Results:")
    for k, v in hybrid_kyber_result.items():
        print(f"  {k}: {v:.6f} cycles")
    
    # Benchmark test_hybrid_tls_falcon
    print("\nRunning test_hybrid_tls_falcon Benchmark...")
    hybrid_falcon_result = test_hybrid_tls_falcon()
    print("Hybrid TLS Falcon Results:")
    for k, v in hybrid_falcon_result.items():
        print(f"  {k}: {v:.6f} cycles")

    # Benchmark test_hybrid_tls_mldsa
    print("\nRunning test_hybrid_tls_mldsa Benchmark...")
    hybrid_mldsa_result = test_hybrid_tls_mldsa()
    print("Hybrid TLS ML-DSA Results:")
    for k, v in hybrid_mldsa_result.items():
        print(f"  {k}: {v:.6f} cycles")


