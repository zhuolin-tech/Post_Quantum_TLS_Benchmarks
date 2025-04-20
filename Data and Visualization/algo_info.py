algo_info = {
    # -------- Single‑algorithm primitives --------
    "RSA 2048": {
        "bits_of_security": 112,
        "public_key_size": 256,
        "private_key_size": 1190,
        "signature_size": 256
    },

    "ECDHE secp256r1": {
        "bits_of_security": 128,
        "public_key_size": 65,
        "private_key_size": 32,
        "signature_size": None
    },

    "ECDSA secp256r1": {
        "bits_of_security": 128,
        "public_key_size": 65,
        "private_key_size": 32,
        "signature_size": 64
    },

    "Kyber768": {
        "bits_of_security": 192,
        "public_key_size": 1184,
        "private_key_size": 2400,
        "ciphertext_size": 1088
    },

    "ML‑DSA (Dilithium3)": {
        "bits_of_security": 192,
        "public_key_size": 1952,
        "private_key_size": 4000,
        "signature_size": 3293
    },

    "Falcon‑512": {
        "bits_of_security": 128,
        "public_key_size": 897,
        "private_key_size": 1281,
        "signature_size": 666
    },

    # -------- Classical TLS suites --------
    "Traditional_TLS_RSA_KEX": {
        "bits_of_security": 112,
        "public_key_size": 256,
        "private_key_size": 1190,
        "signature_size": 256,
        "ciphertext_size": 256
    },

    "Traditional_TLS_ECDHE_RSA": {
        "bits_of_security": 112,
        "public_key_size": 256 + 65,
        "private_key_size": 1190 + 32,
        "signature_size": 256
    },

    "Traditional_TLS_ECDHE_CertSign": {
        "bits_of_security": 128,
        "public_key_size": 65 + 65,
        "private_key_size": 32 + 32,
        "signature_size": 64
    },

    # -------- Hybrid PQ‑TLS suites --------
    "Hybrid_TLS_Kyber": {
        "bits_of_security": 128,
        "public_key_size": 65 + 1184,
        "private_key_size": 32 + 2400,
        "signature_size": 64,
        "ciphertext_size": 1088
    },

    "Hybrid_TLS_Falcon": {
        "bits_of_security": 128,
        "public_key_size": 65 + 1184 + 897,
        "private_key_size": 32 + 2400 + 1281,
        "signature_size": 666,
        "ciphertext_size": 1088
    },

    "Hybrid_TLS_MLDSA": {
        "bits_of_security": 128,
        "public_key_size": 65 + 1184 + 1952,
        "private_key_size": 32 + 2400 + 4000,
        "signature_size": 3293,
        "ciphertext_size": 1088
    }
}
