import time
from cryptographic_algorithm import CryptographicAlgorithms

class CryptographicBenchmark:
    def __init__(self, rounds=10):
        """
        Initialize the benchmark class with cryptographic algorithms and test rounds.
        
        Args:
            rounds: Number of iterations for each benchmark test.
        """
        self.rounds = rounds
        self.crypto = CryptographicAlgorithms()
        self.cpu_cycles = self.crypto.time_to_cpu_kcycles

    # ############## 1. RSA - Rivest-Shamir-Adleman ###############################################

    def test_rsa_keygen(self):
        """
        Benchmarks RSA key generation operations.
        
        Returns:
            List of times (in CPU cycles) to generate RSA key pairs.
        """
        times = []
        for _ in range(self.rounds):
            start = time.perf_counter()
            _ = self.crypto.rsa.keygen()
            times.append(self.cpu_cycles(time.perf_counter() - start))
        return {
            "RSA_keygen": times,
        }

    def test_rsa_sign_and_verify(self):
        """
        Benchmarks RSA signing and verification operations.
        Uses 2048-bit RSA keys.
        
        Returns:
            A dictionary containing:
                - "RSA_sign": List of signing times (in CPU cycles)
                - "RSA_verify": List of verification times (in CPU cycles)
        """
        public_key, private_key = self.crypto.rsa.keygen()
        message = b"Test message for RSA"
        sign_times = []
        verify_times = []

        for _ in range(self.rounds):
            # Measuring the time of signing operations
            sign_start = time.perf_counter()
            signature = self.crypto.rsa.sign(private_key, message)
            sign_end = time.perf_counter()
            sign_times.append(self.cpu_cycles(sign_end - sign_start))

            # Measuring the time of verification operations
            verify_start = time.perf_counter()
            _ = self.crypto.rsa.verify(public_key, signature, message)
            verify_end = time.perf_counter()
            verify_times.append(self.cpu_cycles(verify_end - verify_start))

        return {
            "RSA_sign": sign_times,
            "RSA_verify": verify_times
        }

    def test_rsa_encrypt_and_decrypt(self):
        """
        Benchmarks RSA encryption and decryption operations.
        Uses 2048-bit RSA keys.
        
        Returns:
            Dictionary containing:
                - "RSA_encrypt": List of encryption times (in CPU cycles)
                - "RSA_decrypt": List of decryption times (in CPU cycles)
        """
        public_key, private_key = self.crypto.rsa.keygen()
        data = b"A" * 190  # Sample data, 190 bytes (adjusted to fit RSA OAEP limits)
        encrypt_times = []
        decrypt_times = []

        for _ in range(self.rounds):
            # Measuring the time of encryption operations
            encrypt_start = time.perf_counter()
            ciphertext = self.crypto.rsa.encrypt(public_key, data)
            encrypt_end = time.perf_counter()
            encrypt_times.append(self.cpu_cycles(encrypt_end - encrypt_start))

            # Measuring the time of decryption operations
            decrypt_start = time.perf_counter()
            _ = self.crypto.rsa.decrypt(private_key, ciphertext)
            decrypt_end = time.perf_counter()
            decrypt_times.append(self.cpu_cycles(decrypt_end - decrypt_start))

        return {
            "RSA_encrypt": encrypt_times,
            "RSA_decrypt": decrypt_times
        }

    # ############## 2. ECC - Elliptic Curve Cryptography #########################################

    def test_ecdhe_keygen(self):
        """
        Benchmark the key generation operation for ECDHE.
        
        Returns:
            List of times (in CPU cycles) to generate ECDHE key pairs.
        """
        times = []
        for _ in range(self.rounds):
            start = time.perf_counter()
            _ = self.crypto.ecc.keygen()
            times.append(self.cpu_cycles(time.perf_counter() - start))

        return {
            "ECDHE_keygen": times,
        }


    def test_ecdsa_sign_and_verify(self):
        """
        Benchmark the ECDSA signing and verification operations.
        Uses an ECDHE key pair generated on the SECP256R1 curve.
        
        Returns:
            Dictionary containing:
                - "ECDSA_sign": List of signing times (in CPU cycles)
                - "ECDSA_verify": List of verification times (in CPU cycles)
        """
        public_key, private_key = self.crypto.ecc.keygen()
        message = b"Test message for ECDSA"
        sign_times = []
        verify_times = []
        
        for _ in range(self.rounds):
            # Measuring the time of signing operations
            sign_start = time.perf_counter()
            signature = self.crypto.ecc.sign(private_key, message)
            sign_end = time.perf_counter()
            sign_times.append(self.cpu_cycles(sign_end - sign_start))

            # Measuring the time of verification operations
            verify_start = time.perf_counter()
            _ = self.crypto.ecc.verify(public_key, signature, message)
            verify_end = time.perf_counter()
            verify_times.append(self.cpu_cycles(verify_end - verify_start))
            
        return {
            "ECDSA_sign": sign_times,
            "ECDSA_verify": verify_times
        }

    # ############## 3. Kyber - Post-Quantum Key Encapsulation Mechanism ##########################

    def test_kyber_keygen(self):
        """
        Benchmark the key generation operation for Kyber768.
        
        Returns:
            List of times (in CPU cycles) to generate Kyber768 key pairs.
        """
        times = []
        for _ in range(self.rounds):
            start = time.perf_counter()
            kem, _ = self.crypto.kyber.keygen()
            times.append(self.cpu_cycles(time.perf_counter() - start))
            # Release resources
            kem.free()

        return {
            "Kyber_keygen": times,
        }

    def test_kyber_encapsulate_and_decapsulate(self):
        """
        Benchmark the encapsulation and decapsulation operations for Kyber768.
        
        Returns:
            Dictionary containing:
                - "Kyber_encapsulate": List of encapsulation times (in CPU cycles)
                - "Kyber_decapsulate": List of decapsulation times (in CPU cycles)
        """
        kem, public_key = self.crypto.kyber.keygen()
        encap_times = []
        decap_times = []

        for _ in range(self.rounds):
            # Measure encapsulation time
            encap_start = time.perf_counter()
            enc_time, ciphertext = self.crypto.kyber.encapsulate(kem, public_key)
            encap_end = time.perf_counter()
            encap_times.append(self.cpu_cycles(encap_end - encap_start))

            # Measure decapsulation time
            decap_start = time.perf_counter()
            _ = self.crypto.kyber.decapsulate(kem, ciphertext)
            decap_end = time.perf_counter()
            decap_times.append(self.cpu_cycles(decap_end - decap_start))

        # Free resources associated with the KEM object
        kem.free()

        return {
            "Kyber_encapsulate": encap_times,
            "Kyber_decapsulate": decap_times
        }

    # ############## 4. ML-DSA (CRYSTALS-Dilithium) - Post-Quantum Digital Signature #############

    def test_mldsa_keygen(self):
        """
        Benchmark the key generation operation for ML-DSA (CRYSTALS-Dilithium).
        
        Returns:
            List of times (in CPU cycles) to generate ML-DSA key pairs.
        """
        times = []
        for _ in range(self.rounds):
            start = time.perf_counter()
            private_key, _ = self.crypto.mldsa.keygen()
            times.append(self.cpu_cycles(time.perf_counter() - start))
            # Release resources
            private_key.free()

        return {
            "MLDSA_keygen": times,
        }

    def test_mldsa_sign_and_verify(self):
        """
        Benchmark the ML-DSA signing and verification operations.
        
        Returns:
            Dictionary containing:
                - "MLDSA_sign": List of signing times (in CPU cycles)
                - "MLDSA_verify": List of verification times (in CPU cycles)
        """
        private_key, public_key = self.crypto.mldsa.keygen()
        message = b"Test message for ML-DSA"
        sign_times = []
        verify_times = []

        for _ in range(self.rounds):
            # Measuring the time of signing operations
            sign_start = time.perf_counter()
            signature = self.crypto.mldsa.sign(private_key, message)
            sign_end = time.perf_counter()
            sign_times.append(self.cpu_cycles(sign_end - sign_start))

            # Measuring the time of verification operations
            verify_start = time.perf_counter()
            _ = self.crypto.mldsa.verify(private_key, public_key, signature, message)
            verify_end = time.perf_counter()
            verify_times.append(self.cpu_cycles(verify_end - verify_start))

        # Free resources
        private_key.free()

        return {
            "MLDSA_sign": sign_times,
            "MLDSA_verify": verify_times
        }

    # ############## 5. Falcon - Post-Quantum Digital Signature ##################################

    def test_falcon_keygen(self):
        """
        Benchmark the key generation operation for Falcon.
        
        Returns:
            List of times (in CPU cycles) to generate Falcon key pairs.
        """
        times = []
        for _ in range(self.rounds):
            start = time.perf_counter()
            private_key, _ = self.crypto.falcon.keygen()
            times.append(self.cpu_cycles(time.perf_counter() - start))
            # Release resources
            private_key.free()
            
        return {
            "Falcon_keygen": times,
        }

    def test_falcon_sign_and_verify(self):
        """
        Benchmark the Falcon signing and verification operations.
        
        Returns:
            Dictionary containing:
                - "Falcon_sign": List of signing times (in CPU cycles)
                - "Falcon_verify": List of verification times (in CPU cycles)
        """
        private_key, public_key = self.crypto.falcon.keygen()
        message = b"Test message for Falcon"
        sign_times = []
        verify_times = []

        for _ in range(self.rounds):
            # Measuring the time of signing operations
            sign_start = time.perf_counter()
            signature = self.crypto.falcon.sign(private_key, message)
            sign_end = time.perf_counter()
            sign_times.append(self.cpu_cycles(sign_end - sign_start))

            # Measuring the time of verification operations
            verify_start = time.perf_counter()
            _ = self.crypto.falcon.verify(private_key, public_key, signature, message)
            verify_end = time.perf_counter()
            verify_times.append(self.cpu_cycles(verify_end - verify_start))

        # Free resources
        private_key.free()

        return {
            "Falcon_sign": sign_times,
            "Falcon_verify": verify_times
        }
