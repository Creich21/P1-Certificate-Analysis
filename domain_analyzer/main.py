import csv
import netlas
import os
import json
from dotenv import load_dotenv

import pandas
from extraction import process_domain

load_dotenv()

## python3 -m cert_analyzer.main


if __name__ == "__main__":

    input_path=input("Enter Input path: ").strip()
    output_path=input("Enter Output path: ").strip()


    df=pandas.read_csv(input_path)
    process_domain(df, output_path)
