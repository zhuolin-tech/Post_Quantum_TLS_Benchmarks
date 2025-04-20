import oqs  # Open Quantum Safe library for post-quantum cryptography
import time
import psutil
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import hashes

# Unified Cryptographic Algorithms Class
class CryptographicAlgorithms:
    def __init__(self):
        self.rsa = RSA()
        self.ecc = ECC()
        self.kyber = Kyber()
        self.mldsa = MLDSA()
        self.falcon = Falcon()
    
    @staticmethod
    def time_to_cpu_kcycles(elapsed_s):
        # Current CPU frequency (MHz to Hz)
        freq_hz = psutil.cpu_freq().current * 1e6
        # Returns kilocycles (kilo cycles)
        return elapsed_s * freq_hz / 1e3


# #############################################################################################
# ############## 1. RSA - Rivest-Shamir-Adleman ###############################################
# #############################################################################################
# RSA is one of the first public-key cryptosystems and is widely used for secure data transmission.
# - KeyGen: Generates a 2048-bit RSA key pair with public exponent 65537
# - Sign: Creates a signature using PSS padding with SHA-256 hash
# - Verify: Validates a signature using the same PSS padding and SHA-256 hash
# - Encrypt: Encrypts data using OAEP padding with SHA-256 hash
# - Decrypt: Decrypts data using the same OAEP padding with SHA-256 hash
# #############################################################################################

class RSA:
    def keygen(self):
        """
        Generate an RSA key pair with a 2048-bit modulus.
        Returns:
            public_key: RSA public key used for encryption.
            private_key: RSA private key used for decryption.
        """
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        return public_key, private_key

    def sign(self, private_key, data):
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

    def verify(self, public_key, signature, data):
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

    def encrypt(self, public_key, data):
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

    def decrypt(self, private_key, ciphertext):
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


# #############################################################################################
# ############## 2. ECC - Elliptic Curve Cryptography #########################################
# #############################################################################################
# ECC is a public-key cryptography approach based on the algebraic structure of elliptic curves.
# - KeyGen: Generates an ECDHE key pair using the SECP256R1 (P-256) curve
# - Sign: Creates a signature using ECDSA with SHA-256 hash
# - Verify: Validates an ECDSA signature using SHA-256 hash
# #############################################################################################

class ECC:
    def keygen(self):
        """
        Generate an ephemeral ECDHE key pair using the SECP256R1 elliptic curve.
        Returns:
            public_key: The ECDHE public key.
            private_key: The ECDHE private key.
        """
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        return public_key, private_key

    def sign(self, private_key, data):
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

    def verify(self, public_key, signature, data):
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


# #############################################################################################
# ############## 3. Kyber - Post-Quantum Key Encapsulation Mechanism ##########################
# #############################################################################################
# Kyber is a lattice-based key encapsulation mechanism (KEM) resistant to quantum attacks.
# - KeyGen: Generates a Kyber768 key pair for post-quantum key exchange
# - Encrypt: Creates a ciphertext and shared secret using the public key
# - Decrypt: Recovers the shared secret from the ciphertext using the private key
# #############################################################################################

class Kyber:
    def keygen(self):
        """
        Generate a key pair using the post-quantum key encapsulation mechanism (KEM) Kyber768.
        Returns:
            kem: The KEM object instance.
            public_key: The generated public key.
        """
        kem = oqs.KeyEncapsulation("Kyber768")
        public_key = kem.generate_keypair()
        return kem, public_key

    def encapsulate(self, kem, public_key):
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

    def decapsulate(self, kem, ciphertext):
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


# #############################################################################################
# ############## 4. ML-DSA (CRYSTALS-Dilithium) - Post-Quantum Digital Signature #############
# #############################################################################################
# ML-DSA (formerly CRYSTALS-Dilithium) is a lattice-based digital signature scheme resistant to quantum attacks.
# - KeyGen: Generates a Dilithium3 key pair for post-quantum digital signatures
# - Sign: Creates a signature using the Dilithium3 algorithm
# - Verify: Validates a Dilithium3 signature
# #############################################################################################

class MLDSA:
    def keygen(self):
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

    def sign(self, private_key, data):
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

    def verify(self, private_key, public_key, signature, data):
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


# #############################################################################################
# ############## 5. Falcon - Post-Quantum Digital Signature ##################################
# #############################################################################################
# Falcon is a lattice-based digital signature scheme based on NTRU lattices, resistant to quantum attacks.
# - KeyGen: Generates a Falcon-512 key pair for post-quantum digital signatures
# - Sign: Creates a signature using the Falcon-512 algorithm
# - Verify: Validates a Falcon-512 signature
# #############################################################################################

class Falcon:
    def keygen(self):
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

    def sign(self, private_key, data):
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

    def verify(self, private_key, public_key, signature, data):
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
