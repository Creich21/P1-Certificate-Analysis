import pandas as pd
import json

blocklist_df = pd.read_json("blocklist.json")

# Drop duplicate domain names, keeping the last
blocklist_df = blocklist_df.drop_duplicates(subset="domain_name", keep="last")

blocklist_dict = blocklist_df.set_index("domain_name").to_dict(orient="index")


json_domains = set(blocklist_dict.keys())

matched = []
unmatched = []

for chunk in pd.read_csv("AUU_projekt.csv", chunksize=10000):
    matched_chunk = chunk[chunk["Domæne"].isin(json_domains)]

    # if the domain is in blocklist, enter
    if not matched_chunk.empty:
        for _, row in matched_chunk.iterrows():
            # iterate through the matched domains in the chunk, grab the info from abusemanager
            domain = row["Domæne"]
            csv_entry = row.to_dict()
            abusemanager_info = blocklist_dict.get(domain, {})

            # merge into new dictionary, making abusemanager_info a new field in the json
            merged_entry = {**csv_entry, "abusemanager_info": abusemanager_info}
            matched.append(merged_entry)
    else:
        unmatched.append(chunk)


# parse the lists of matched/unmatched to pandas dataframes, export them as json
result_matched_df = pd.DataFrame(matched)
result_unmatched_df = pd.concat(unmatched, ignore_index=True)

result_unmatched_df.to_json("unmatched.json", orient="records", indent=2, force_ascii=False)
result_matched_df.to_json("matched.json", orient="records", indent=2, force_ascii=False)
