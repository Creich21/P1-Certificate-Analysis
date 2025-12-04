import pandas as pd
from pathlib import Path


def load_domains_from_csv(file_path, sheet_name='Sheet1', column_name='Domain'):
    df = pd.read_csv(file_path,sep=';')
    domains = df[column_name].dropna().tolist()
    return domains


def get_blocked_domains() -> list[str]:
    base_dir = Path(__file__).resolve().parent
    project_root = base_dir.parent
    data_dir = project_root / "data"
    csv_path = data_dir / "popular_domain_features.csv"
    return load_domains_from_csv(csv_path)


