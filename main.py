import os
import csv
import statistics
from benchmark_tls import TLSBenchmark
from benchmark_crypto import CryptographicBenchmark

def save_benchmark_csv(title, mean, standard_deviation, max_value, min_value):
    """
    Saves a single benchmark result to a CSV file.
    Args:
        title (str): Benchmark name.
        mean (float): Average value.
        standard_deviation (float): Standard deviation.
        max_value (float): Maximum value observed.
        min_value (float): Minimum value observed.
    """
    # Create results directory if it doesn't exist
    filename = f"Data and Visualization/benchmark_data.csv"
    csv_path = os.path.join(filename)
    
    # Write results to CSV
    file_exists = os.path.isfile(csv_path)
    with open(csv_path, 'a', newline='') as csvfile:
        writer = csv.writer(csvfile)
        if not file_exists:
            writer.writerow(["Title", "Mean", "Std", "Max", "Min"])

        writer.writerow([title, f"{mean:.6f}", f"{standard_deviation:.6f}", f"{max_value:.6f}", f"{min_value:.6f}"])

def print_benchmark_results(results):
    """
    Prints the benchmark results in a formatted table.
    Args:
        results (dict): A dictionary containing benchmark results.
    """
    for title, value in results.items():
        mean = statistics.mean(value)
        standard_deviation = statistics.stdev(value)
        max_value = max(value)
        min_value = min(value)
        print(f"{title}: {mean:.6f} kilo cycles (±{standard_deviation:.6f}), max: {max_value:.6f}, min: {min_value:.6f}")
        save_benchmark_csv(title, mean, standard_deviation, max_value, min_value)



if __name__ == "__main__":

    rounds = 1000  # Number of iterations for each benchmark test

    # Creating a benchmark instance
    crypto_benchmark = CryptographicBenchmark(rounds)
    tls_benchmark = TLSBenchmark(rounds)

    # ##################################################
    # ============ 1. Algorithm Performance ============
    # ##################################################

    # Benchmark RSA Algorithm Performance
    print("\nRunning RSA Key Generation, Encryption and Decryption Benchmark...")
    rsa_keygen_times = crypto_benchmark.test_rsa_keygen()
    rsa_sign_verify_result = crypto_benchmark.test_rsa_sign_and_verify()
    rsa_encrypt_decrypt_result = crypto_benchmark.test_rsa_encrypt_and_decrypt()
    print_benchmark_results(rsa_keygen_times)
    print_benchmark_results(rsa_sign_verify_result)
    print_benchmark_results(rsa_encrypt_decrypt_result)

    # Benchmark Elliptic Curve Algorithm Performance
    print("\nRunning Elliptic Curve Key Generation, Signing and Verification Benchmark...")
    ecdhe_keygen_times = crypto_benchmark.test_ecdhe_keygen()
    ecdsa_sign_verify_result = crypto_benchmark.test_ecdsa_sign_and_verify()
    print_benchmark_results(ecdhe_keygen_times)
    print_benchmark_results(ecdsa_sign_verify_result)

    # Benchmark Kyber Algorithm Performance
    print("\nRunning Kyber Key Generation Benchmark...")
    kyber_keygen_times = crypto_benchmark.test_kyber_keygen()
    kyber_encap_decap_result = crypto_benchmark.test_kyber_encapsulate_and_decapsulate()
    print_benchmark_results(kyber_keygen_times)
    print_benchmark_results(kyber_encap_decap_result)

    # Benchmark ML-DSA Algorithm Performance
    print("\nRunning ML-DSA Key Generation and Signing Benchmark...")
    mldsa_keygen_times = crypto_benchmark.test_mldsa_keygen()
    mldsa_sign_verify_result = crypto_benchmark.test_mldsa_sign_and_verify()
    print_benchmark_results(mldsa_keygen_times)
    print_benchmark_results(mldsa_sign_verify_result)

    # Benchmark Falcon Algorithm Performance
    print("\nRunning Falcon Key Generation and Signing Benchmark...")
    falcon_keygen_times = crypto_benchmark.test_falcon_keygen()
    falcon_sign_verify_result = crypto_benchmark.test_falcon_sign_and_verify()
    print_benchmark_results(falcon_keygen_times)
    print_benchmark_results(falcon_sign_verify_result)

    # ##################################################
    # ============ 2. TLS Performance ==================
    # ##################################################

    # Benchmark test_traditional_tls_rsa_kex
    print("\nRunning Traditional TLS RSA Key Exchange Benchmark...")
    trad_rsa_kex_result = tls_benchmark.test_traditional_tls_rsa_kex()
    print_benchmark_results(trad_rsa_kex_result)

    # Benchmark test_traditional_tls_ecdhe_rsa
    print("\nRunning Traditional TLS ECDHE RSA Key Exchange Benchmark...")
    trad_ecdhe_rsa_result = tls_benchmark.test_traditional_tls_ecdhe_rsa()
    print_benchmark_results(trad_ecdhe_rsa_result)

    # Benchmark test_traditional_tls_ecdhe_certsign
    print("\nRunning Traditional TLS ECDHE CertSign Key Exchange Benchmark...")
    trad_ecdhe_certsign_result = tls_benchmark.test_traditional_tls_ecdhe_certsign()
    print_benchmark_results(trad_ecdhe_certsign_result)

    # Benchmark test_hybrid_tls_kyber
    print("\nRunning Hybrid TLS Kyber Key Exchange Benchmark...")
    hybrid_kyber_result = tls_benchmark.test_hybrid_tls_kyber()
    print_benchmark_results(hybrid_kyber_result)

    # Benchmark test_hybrid_tls_falcon
    print("\nRunning Hybrid TLS Falcon Key Exchange Benchmark...")
    hybrid_falcon_result = tls_benchmark.test_hybrid_tls_falcon()
    print_benchmark_results(hybrid_falcon_result)

    # Benchmark test_hybrid_tls_mldsa
    print("\nRunning Hybrid TLS ML-DSA Key Exchange Benchmark...")
    hybrid_mldsa_result = tls_benchmark.test_hybrid_tls_mldsa()
    print_benchmark_results(hybrid_mldsa_result)
