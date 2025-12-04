import csv
import matplotlib.pyplot as plt

def plot_field_stats(csv_file="hypothesis/csv_plots/field_stats.csv", top_n=10):
    fields = []
    counts = []

    with open(csv_file, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            fields.append(row["field"])
            counts.append(int(row["missing_count"]))

    # sort and take top N
    pairs = sorted(zip(fields, counts), key=lambda x: x[1], reverse=True)[:top_n]
    fields, counts = zip(*pairs)

    plt.figure(figsize=(10, 5))
    plt.bar(fields, counts)
    plt.xticks(rotation=45, ha="right")
    plt.ylabel("Missing count")
    plt.title("Top missing certificate fields")
    plt.tight_layout()
    plt.show()


def plot_missing_fields_distribution(csv_file="hypothesis/csv_plots/missing_count_dist.csv"):
    """Plot distribution of certificates by number of missing fields"""
    num_missing = []
    num_certs = []

    with open(csv_file, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            num_missing.append(int(row["num_missing_fields"]))
            num_certs.append(int(row["num_certificates"]))

    plt.figure(figsize=(12, 6))
    plt.bar(num_missing, num_certs, color='steelblue', edgecolor='black')
    plt.xlabel("Number of Missing Fields", fontsize=12)
    plt.ylabel("Number of Certificates", fontsize=12)
    plt.title("Distribution of Certificates by Number of Missing Fields", fontsize=14, fontweight='bold')
    plt.xticks(num_missing)
    plt.grid(axis='y', alpha=0.3)
    
    # Add value labels on top of bars
    for i, v in enumerate(num_certs):
        plt.text(num_missing[i], v + max(num_certs)*0.01, str(v), 
                ha='center', va='bottom', fontsize=9)
    
    plt.tight_layout()
    plt.show()




def plot_overview(csv_file: str = "hypothesis/csv_plots/overview_stats.csv") -> None:
    labels = []
    values = []

    with open(csv_file, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            labels.append(row["metric"])
            values.append(int(row["value"]))

    if not values:
        print("No data to plot.")
        return

    plt.figure(figsize=(6, 4))
    plt.bar(labels, values, color=["red", "green", "blue"])
    plt.ylabel("Count")
    plt.title("Overview: domains and certificates")
    plt.tight_layout()
    plt.show()


def plot_validation_level_distribution():
    """Plot distribution of certificates by validation level"""
    validation_levels = ["DV", "unknown", "OV", "EV"]
    counts = [38720, 360, 1016, 39]


    
    plt.figure(figsize=(8, 6))
    bars = plt.bar(validation_levels, counts, color=['skyblue', 'lightcoral', 'lightgreen', 'gold'], 
                   edgecolor='black')
    
    plt.xlabel("Validation Level", fontsize=12)
    plt.ylabel("Number of Certificates", fontsize=12)
    plt.title("Distribution of Certificates by Validation Level", fontsize=14, fontweight='bold')
    
    # Add value labels on top of bars
    for bar, count in zip(bars, counts):
        plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(counts)*0.01, 
                str(count), ha='center', va='bottom', fontsize=10)
    
    plt.grid(axis='y', alpha=0.3)
    plt.tight_layout()
    plt.show()



if __name__ == "__main__":
    # plot_field_stats()
    # plot_missing_fields_distribution()
    # plot_overview()
    plot_validation_level_distribution()