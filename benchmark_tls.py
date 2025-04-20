import time
from cryptographic_algorithm import CryptographicAlgorithms

class TLSBenchmark:
    def __init__(self, rounds=10):
        """
        Initialize the TLS benchmark class with cryptographic algorithms and test rounds.
        
        Args:
            rounds: Number of iterations for each benchmark test.
        """
        self.rounds = rounds
        self.crypto = CryptographicAlgorithms()
        self.cpu_cycles = self.crypto.time_to_cpu_kcycles


    def test_traditional_tls_rsa_kex(self):
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
        # Pre-define lists for collecting timing data
        keygen_time = []
        cert_verify_time = []
        encrypt_time = []
        decrypt_time = []
        total_time = []

        for _ in range(self.rounds):
            # Measure RSA key generation time
            start_first = time.perf_counter()
            public_key, private_key = self.crypto.rsa.keygen()
            keygen_time.append(self.cpu_cycles(time.perf_counter() - start_first))

            # Simulate certificate verification (using RSA verify as proxy)
            cert_data = b"TLS Certificate Chain Data"
            # Generate a signature for the certificate data
            cert_signature = self.crypto.rsa.sign(private_key, cert_data)

            start = time.perf_counter()
            _ = self.crypto.rsa.verify(public_key, cert_signature, cert_data)
            cert_verify_time.append(self.cpu_cycles(time.perf_counter() - start))

            # Measure RSA encryption of pre-master secret
            pre_master_secret = b"A" * 190  # Simulated pre-master secret

            start = time.perf_counter()
            ciphertext = self.crypto.rsa.encrypt(public_key, pre_master_secret)
            encrypt_time.append(self.cpu_cycles(time.perf_counter() - start))

            # Measure RSA decryption of pre-master secret
            start = time.perf_counter()
            _ = self.crypto.rsa.decrypt(private_key, ciphertext)
            decrypt_time.append(self.cpu_cycles(time.perf_counter() - start))
            total_time.append(self.cpu_cycles(time.perf_counter() - start_first))

        return {
            "RSA_keygen": keygen_time,
            "Cert_verify": cert_verify_time,
            "RSA_encrypt": encrypt_time,
            "RSA_decrypt": decrypt_time,
            "Total_time": total_time
        }

    def test_traditional_tls_ecdhe_rsa(self):
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
        # Pre-define lists for collecting timing data
        ecdhe_keygen_time = []
        rsa_sign_time = []
        rsa_verify_time = []
        encrypt_time = []
        decrypt_time = []
        total_time = []

        for _ in range(self.rounds):
            # Generate RSA keys for certificate operations
            rsa_pub_key, rsa_priv_key = self.crypto.rsa.keygen()

            # Measure ECDHE key generation time
            start_first = time.perf_counter()
            ec_pub_key, ec_priv_key = self.crypto.ecc.keygen()
            ecdhe_keygen_time.append(self.cpu_cycles(time.perf_counter() - start_first))

            # Simulate ServerKeyShare data
            server_key_share = b"ECDHE Server Key Share Data"

            # Measure RSA signing time for ServerKeyShare
            start = time.perf_counter()
            signature = self.crypto.rsa.sign(rsa_priv_key, server_key_share)
            rsa_sign_time.append(self.cpu_cycles(time.perf_counter() - start))

            # Measure RSA verification time
            start = time.perf_counter()
            _ = self.crypto.rsa.verify(rsa_pub_key, signature, server_key_share)
            rsa_verify_time.append(self.cpu_cycles(time.perf_counter() - start))

            # Simulate symmetric encryption/decryption using RSA as a proxy
            # (In real TLS, this would use AES or another symmetric cipher)
            finished_message = b"TLS Finished Message"

            # Encrypt using RSA as a proxy for symmetric encryption
            start = time.perf_counter()
            ciphertext = self.crypto.rsa.encrypt(rsa_pub_key, finished_message[:190])  # Truncate to fit RSA
            encrypt_time.append(self.cpu_cycles(time.perf_counter() - start))

            # Decrypt using RSA as a proxy for symmetric decryption
            start = time.perf_counter()
            _ = self.crypto.rsa.decrypt(rsa_priv_key, ciphertext)
            decrypt_time.append(self.cpu_cycles(time.perf_counter() - start))
            total_time.append(self.cpu_cycles(time.perf_counter() - start_first))

        return {
            "ECDHE_keygen": ecdhe_keygen_time,
            "RSA_sign": rsa_sign_time,
            "RSA_verify": rsa_verify_time,
            "Finished_encrypt": encrypt_time,
            "Finished_decrypt": decrypt_time,
            "Total_time": total_time
        }

    def test_traditional_tls_ecdhe_certsign(self):
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
        # Pre-define lists for collecting timing data
        ecdhe_keygen_time = []
        cert_sign_time = []
        cert_verify_time = []
        encrypt_time = []
        decrypt_time = []
        total_time = []

        for _ in range(self.rounds):
            # Measure ECDHE key generation time
            start_first = time.perf_counter()
            ec_pub_key, ec_priv_key = self.crypto.ecc.keygen()
            ecdhe_keygen_time.append(self.cpu_cycles(time.perf_counter() - start_first))

            # Simulate handshake transcript data
            handshake_transcript = b"TLS 1.3 Handshake Transcript Data"

            # Measure ECDSA signing time for certificate
            start = time.perf_counter()
            signature = self.crypto.ecc.sign(ec_priv_key, handshake_transcript)
            cert_sign_time.append(self.cpu_cycles(time.perf_counter() - start))

            # Measure ECDSA verification time
            start = time.perf_counter()
            _ = self.crypto.ecc.verify(ec_pub_key, signature, handshake_transcript)
            cert_verify_time.append(self.cpu_cycles(time.perf_counter() - start))

            # Generate RSA keys to simulate symmetric encryption (as a proxy)
            rsa_pub_key, rsa_priv_key = self.crypto.rsa.keygen()

            # Simulate Finished/0-RTT message
            finished_message = b"TLS 1.3 Finished Message"

            # Encrypt using RSA as a proxy for symmetric encryption
            start = time.perf_counter()
            ciphertext = self.crypto.rsa.encrypt(rsa_pub_key, finished_message[:190])  # Truncate to fit RSA
            encrypt_time.append(self.cpu_cycles(time.perf_counter() - start))

            # Decrypt using RSA as a proxy for symmetric decryption
            start = time.perf_counter()
            _ = self.crypto.rsa.decrypt(rsa_priv_key, ciphertext)
            decrypt_time.append(self.cpu_cycles(time.perf_counter() - start))
            total_time.append(self.cpu_cycles(time.perf_counter() - start_first))

        return {
            "ECDHE_keygen": ecdhe_keygen_time,
            "CertSign_sign": cert_sign_time,
            "CertSign_verify": cert_verify_time,
            "Finished_encrypt": encrypt_time,
            "Finished_decrypt": decrypt_time,
            "Total_time": total_time
        }


    def test_hybrid_tls_kyber(self):
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
        # Pre-define lists for collecting timing data
        ecdhe_keygen_time = []
        kyber_keygen_time = []
        cert_sign_time = []
        cert_verify_time = []
        kyber_encap_time = []
        kyber_decap_time = []
        total_time = []

        for _ in range(self.rounds):
            # Measure ECDHE key generation time
            start_first = time.perf_counter()
            ec_pub_key, ec_priv_key = self.crypto.ecc.keygen()
            ecdhe_keygen_time.append(self.cpu_cycles(time.perf_counter() - start_first))

            # Measure Kyber key generation time
            start = time.perf_counter()
            kem, kyber_pub_key = self.crypto.kyber.keygen()
            kyber_keygen_time.append(self.cpu_cycles(time.perf_counter() - start))

            # Simulate handshake transcript data
            handshake_transcript = b"Hybrid TLS Handshake Transcript Data"

            # Measure ECDSA signing time for certificate
            start = time.perf_counter()
            signature = self.crypto.ecc.sign(ec_priv_key, handshake_transcript)
            cert_sign_time.append(self.cpu_cycles(time.perf_counter() - start))

            # Measure ECDSA verification time
            start = time.perf_counter()
            _ = self.crypto.ecc.verify(ec_pub_key, signature, handshake_transcript)
            cert_verify_time.append(self.cpu_cycles(time.perf_counter() - start))

            # Measure Kyber encapsulation time
            encap_time, ciphertext = self.crypto.kyber.encapsulate(kem, kyber_pub_key)
            kyber_encap_time.append(self.cpu_cycles(encap_time))

            # Measure Kyber decapsulation time
            decap_time = self.crypto.kyber.decapsulate(kem, ciphertext)
            kyber_decap_time.append(self.cpu_cycles(decap_time))
            total_time.append(self.cpu_cycles(time.perf_counter() - start_first))

            # Free Kyber resources
            kem.free()

        return {
            "ECDHE_keygen": ecdhe_keygen_time,
            "Kyber_keygen": kyber_keygen_time,
            "CertSign_sign": cert_sign_time,
            "CertSign_verify": cert_verify_time,
            "Kyber_encapsulate": kyber_encap_time,
            "Kyber_decapsulate": kyber_decap_time,
            "Total_time": total_time
        }


    def test_hybrid_tls_falcon(self):
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
        # Pre-define lists for collecting timing data
        ecdhe_keygen_time = []
        kyber_keygen_time = []
        falcon_sign_time = []
        falcon_verify_time = []
        cert_verify_time = []
        kyber_encap_time = []
        kyber_decap_time = []
        total_time = []

        for _ in range(self.rounds):
            # Measure ECDHE key generation time
            start_first = time.perf_counter()
            ec_pub_key, ec_priv_key = self.crypto.ecc.keygen()
            ecdhe_keygen_time.append(self.cpu_cycles(time.perf_counter() - start_first))

            # Measure Kyber key generation time
            start = time.perf_counter()
            kem, kyber_pub_key = self.crypto.kyber.keygen()
            kyber_keygen_time.append(self.cpu_cycles(time.perf_counter() - start))

            # Generate Falcon keys
            falcon_priv_key, falcon_pub_key = self.crypto.falcon.keygen()

            # Simulate handshake transcript data
            handshake_transcript = b"Hybrid TLS with Falcon Handshake Transcript Data"

            # Measure Falcon signing time
            start = time.perf_counter()
            signature = self.crypto.falcon.sign(falcon_priv_key, handshake_transcript)
            falcon_sign_time.append(self.cpu_cycles(time.perf_counter() - start))

            # Measure Falcon verification time
            start = time.perf_counter()
            _ = self.crypto.falcon.verify(falcon_priv_key, falcon_pub_key, signature, handshake_transcript)
            falcon_verify_time.append(self.cpu_cycles(time.perf_counter() - start))

            # Simulate certificate verification (using ECDSA as proxy for classic certs)
            cert_data = b"TLS Certificate Chain Data"
            cert_signature = self.crypto.ecc.sign(ec_priv_key, cert_data)

            start = time.perf_counter()
            _ = self.crypto.ecc.verify(ec_pub_key, cert_signature, cert_data)
            cert_verify_time.append(self.cpu_cycles(time.perf_counter() - start))

            # Measure Kyber encapsulation time
            encap_time, ciphertext = self.crypto.kyber.encapsulate(kem, kyber_pub_key)
            kyber_encap_time.append(self.cpu_cycles(encap_time))

            # Measure Kyber decapsulation time
            decap_time = self.crypto.kyber.decapsulate(kem, ciphertext)
            kyber_decap_time.append(self.cpu_cycles(decap_time))
            total_time.append(self.cpu_cycles(time.perf_counter() - start_first))

            # Free resources
            kem.free()
            falcon_priv_key.free()

        return {
            "ECDHE_keygen": ecdhe_keygen_time,
            "Kyber_keygen": kyber_keygen_time,
            "Falcon_sign": falcon_sign_time,
            "Falcon_verify": falcon_verify_time,
            "Cert_verify": cert_verify_time,
            "Kyber_encapsulate": kyber_encap_time,
            "Kyber_decapsulate": kyber_decap_time,
            "Total_time": total_time
        }


    def test_hybrid_tls_mldsa(self):
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
        # Pre-define lists for collecting timing data
        ecdhe_keygen_time = []
        kyber_keygen_time = []
        mldsa_keygen_time = []
        mldsa_sign_time = []
        mldsa_verify_time = []
        cert_verify_time = []
        kyber_encap_time = []
        kyber_decap_time = []
        total_time = []

        for _ in range(self.rounds):
            # Measure ECDHE key generation time
            start_first = time.perf_counter()
            ec_pub_key, ec_priv_key = self.crypto.ecc.keygen()
            ecdhe_keygen_time.append(self.cpu_cycles(time.perf_counter() - start_first))

            # Measure Kyber key generation time
            start = time.perf_counter()
            kem, kyber_pub_key = self.crypto.kyber.keygen()
            kyber_keygen_time.append(self.cpu_cycles(time.perf_counter() - start))

            # Measure ML-DSA key generation time
            start = time.perf_counter()
            mldsa_priv_key, mldsa_pub_key = self.crypto.mldsa.keygen()
            mldsa_keygen_time.append(self.cpu_cycles(time.perf_counter() - start))

            # Simulate handshake transcript data
            handshake_transcript = b"Hybrid TLS with ML-DSA Handshake Transcript Data"

            # Measure ML-DSA signing time
            start = time.perf_counter()
            signature = self.crypto.mldsa.sign(mldsa_priv_key, handshake_transcript)
            mldsa_sign_time.append(self.cpu_cycles(time.perf_counter() - start))

            # Measure ML-DSA verification time
            start = time.perf_counter()
            _ = self.crypto.mldsa.verify(mldsa_priv_key, mldsa_pub_key, signature, handshake_transcript)
            mldsa_verify_time.append(self.cpu_cycles(time.perf_counter() - start))

            # Simulate certificate verification (using ECDSA as proxy for classic certs)
            cert_data = b"TLS Certificate Chain Data"
            cert_signature = self.crypto.ecc.sign(ec_priv_key, cert_data)

            start = time.perf_counter()
            _ = self.crypto.ecc.verify(ec_pub_key, cert_signature, cert_data)
            cert_verify_time.append(self.cpu_cycles(time.perf_counter() - start))

            # Measure Kyber encapsulation time
            encap_time, ciphertext = self.crypto.kyber.encapsulate(kem, kyber_pub_key)
            kyber_encap_time.append(self.cpu_cycles(encap_time))

            # Measure Kyber decapsulation time
            decap_time = self.crypto.kyber.decapsulate(kem, ciphertext)
            kyber_decap_time.append(self.cpu_cycles(decap_time))
            total_time.append(self.cpu_cycles(time.perf_counter() - start_first))

            # Free resources
            kem.free()
            mldsa_priv_key.free()

        return {
            "ECDHE_keygen": ecdhe_keygen_time,
            "Kyber_keygen": kyber_keygen_time,
            "MLDSA_keygen": mldsa_keygen_time,
            "MLDSA_sign": mldsa_sign_time,
            "MLDSA_verify": mldsa_verify_time,
            "Cert_verify": cert_verify_time,
            "Kyber_encapsulate": mldsa_keygen_time,
            "Kyber_decapsulate": kyber_decap_time,
            "Total_time": total_time
        }
