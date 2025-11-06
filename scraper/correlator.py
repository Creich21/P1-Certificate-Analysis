import pandas as pd
import json

# import blocklist json and parse it
blocklist_df = pd.read_json("blocklist.json")
json_domains = set(blocklist_df["domain_name"])

matched = []

# read through the csv file in chunks of 10000 rows
for chunk in pd.read_csv("AUU_projekt.csv", chunksize=10000):
    # check if the value in the domain is in the set of domains from the blocklist
    matched_chunk = chunk[chunk["Domæne"].isin(json_domains)]

    # if domain is in blocklist, merge the two entries
    if not matched_chunk.empty:
        merged = matched_chunk.merge(blocklist_df, left_on="Domæne", right_on="domain_name", suffixes=("_csv", "_json"))
        # remove field from new dict (this one is duplicate
        # to remove others, just add the key name to the array
        merged = merged.drop(columns=["domain_name"])
        matched.append(merged)


# parse the list of matched entries to a pandas dataframe, export it as json
result_df = pd.concat(matched, ignore_index=True)
result_df.to_json("matched.json", orient="records", indent=2, force_ascii=False)
