import pandas as pd

def merge_features():
    domain_features_path = input("Enter the path for domain_features.csv: ")
    cert_features_path = input("Enter the path for cert_features.csv: ")
    output_path = input("Enter the output path for merged features csv: ")

    domain_df = pd.read_csv(domain_features_path)
    cert_df = pd.read_csv(cert_features_path)

    merged= pd.merge(cert_df, domain_df, on=["BrugerId", "Domæne", "OprettetDato", "RegistrantValideret", "RegistrantLand", "label"], how='left')

    merged.to_csv(output_path, index=False)

if __name__=="__main__":
    merge_features()