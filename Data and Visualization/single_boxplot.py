import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
import os

# Extract boxplot data processing logic into a separate function
def prepare_boxplot_data(data):
    # Extract algorithm operation names
    algorithms = data['Title'].tolist()

    # Get data columns
    means = data['Mean'].tolist()
    stds = data['Std'].tolist()
    maxs = data['Max'].tolist()
    mins = data['Min'].tolist()

    # Construct five-number summary data for boxplot: min, Q1, median, Q3, max
    box_data = []
    for i in range(len(algorithms)):
        mean = means[i]
        std = stds[i]
        max_val = maxs[i]
        min_val = mins[i]

        # Assume Q1 and Q3 are symmetrically distributed around the mean, prevent out of bounds
        median = mean
        q1 = max(mean - 0.67 * std, min_val)
        q3 = min(mean + 0.67 * std, max_val)

        # Take log10 transformation
        simulated_data = np.log10([min_val * 1000, q1 * 1000, median * 1000, q3 * 1000, max_val * 1000])
        box_data.append(simulated_data)
    
    return box_data, algorithms

# Create function to draw boxplot
def plot_boxplot(data, savepath, title, filename):
    plt.figure(figsize=(12, 8))

    # Call data processing function to get boxplot data
    box_data, algorithms = prepare_boxplot_data(data)

    # Draw boxplot
    bp = plt.boxplot(box_data, tick_labels=algorithms, patch_artist=True, showmeans=True,
                     meanprops={'marker': 'D', 'markerfacecolor': 'green', 'markeredgecolor': 'green', 'markersize': 10})

    # Beautify appearance
    for box in bp['boxes']:
        box.set(facecolor='lightblue', alpha=0.8)
    for whisker in bp['whiskers']:
        whisker.set(color='gray', linewidth=1.5, linestyle='--')
    for cap in bp['caps']:
        cap.set(color='gray', linewidth=2)
    for median in bp['medians']:
        median.set(color='red', linewidth=2)

    # Add title and labels - increase font size
    plt.title(title, fontsize=20, fontweight='bold')
    plt.ylabel('log10 CPU Cycles', fontsize=22)
    plt.xticks(rotation=0, ha='center', fontsize=16)

    # Add legend explanation - increase legend font size
    plt.scatter([], [], color='green', marker='D', s=100, label='Mean')
    plt.scatter([], [], color='red', marker='_', s=100, linewidth=3, label='Median')
    plt.legend(fontsize=16)

    # Auto-adjust layout and save image locally
    plt.tight_layout()
    output_file = os.path.join(savepath, f'{filename}.png')
    plt.savefig(output_file, dpi=300)
    plt.show()
    plt.close()

# Extract data for a specific algorithm group from the dataset
def extract_algorithm_group(df, algorithm_prefixes):
    dfs = []
    for prefix in algorithm_prefixes:
        matching_rows = df[df['Title'].str.startswith(prefix)]
        if not matching_rows.empty:
            dfs.append(matching_rows)
    if dfs:
        return pd.concat(dfs, ignore_index=True)
    else:
        return pd.DataFrame(columns=['Title', 'Mean', 'Std', 'Max', 'Min'])  # Return empty structure if no matches


if __name__ == "__main__":

    plt.style.use('default')  # Use default white background
    sns.set_palette("pastel")

    # Default read CSV file from current directory
    csv_path = './benchmark_data.csv'
    savepath = 'single boxplot/'
    df = pd.read_csv(csv_path)

    # Extract and plot RSA algorithm group
    rsa_data = extract_algorithm_group(df, ['RSA_keygen', 'RSA_sign', 'RSA_verify', 'RSA_encrypt', 'RSA_decrypt'])
    rsa_data = rsa_data.head(5)
    plot_boxplot(rsa_data, savepath, 'RSA Performance', 'rsa_boxplot')

    # Extract and plot ECDSA algorithm group
    ecdsa_data = extract_algorithm_group(df, ['ECDHE_keygen', 'ECDSA_sign', 'ECDSA_verify'])
    ecdsa_data = ecdsa_data.head(3)
    plot_boxplot(ecdsa_data, savepath, 'ECDSA Performance', 'ecdsa_boxplot')

    # Extract and plot Kyber algorithm group
    kyber_data = extract_algorithm_group(df, ['Kyber_keygen', 'Kyber_encapsulate', 'Kyber_decapsulate'])
    kyber_data = kyber_data.head(3)
    plot_boxplot(kyber_data, savepath, 'Kyber Performance', 'kyber_boxplot')

    # Extract and plot MLDSA algorithm group
    mldsa_data = extract_algorithm_group(df, ['MLDSA_keygen', 'MLDSA_sign', 'MLDSA_verify'])
    mldsa_data = mldsa_data.head(3)
    plot_boxplot(mldsa_data, savepath, 'MLDSA Performance', 'mldsa_boxplot')

    # Extract and plot Falcon algorithm group
    falcon_data = extract_algorithm_group(df, ['Falcon_keygen', 'Falcon_sign', 'Falcon_verify'])
    falcon_data = falcon_data.head(3)
    plot_boxplot(falcon_data, savepath, 'Falcon Performance', 'falcon_boxplot')

    print("All boxplots have been successfully generated!")
