import csv
import re

# ==========================
# 🔧 CONFIGURE THESE PATHS
# ==========================
BIB_PATH = r"final.bib"       # Path to your .bib file
CSV_PATH = r"final.csv"      # Where to save the .csv file
# ==========================


def parse_bib_file(bib_path):
    """Parse a .bib file into a list of dictionaries."""
    with open(bib_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Split individual entries
    entries = re.split(r'@', content)
    parsed_entries = []

    for entry in entries:
        if not entry.strip():
            continue

        # Extract type and citation key (e.g., ARTICLE{Ibrahim2025,)
        header_match = re.match(r'(\w+)\s*\{([^,]+),', entry, re.DOTALL)
        if not header_match:
            continue

        entry_type = header_match.group(1).strip()
        citation_key = header_match.group(2).strip()

        fields = {
            "entry_type": entry_type,
            "citation_key": citation_key
        }

        # Extract key=value pairs like key = {value}
        for match in re.finditer(r'(\w+)\s*=\s*\{(.*?)\}', entry, re.DOTALL):
            key = match.group(1).strip().lower()  # normalize to lowercase
            value = match.group(2).strip().replace('\n', ' ')
            # Merge duplicates gracefully — prefer the first seen
            if key not in fields:
                fields[key] = value

        parsed_entries.append(fields)

    return parsed_entries


def write_csv(entries, csv_path):
    """Write parsed BibTeX entries to a CSV file."""
    # Collect all unique field names (case-insensitive)
    all_fields = set()
    for e in entries:
        all_fields.update(e.keys())
    all_fields = sorted(all_fields)

    with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=all_fields)
        writer.writeheader()
        for e in entries:
            # Ensure all keys exist (missing fields become empty)
            row = {field: e.get(field, "") for field in all_fields}
            writer.writerow(row)


def main():
    print(f"Parsing {BIB_PATH} ...")
    entries = parse_bib_file(BIB_PATH)
    print(f"Found {len(entries)} entries.")

    print(f"Writing {CSV_PATH} ...")
    write_csv(entries, CSV_PATH)
    print("✅ Done! CSV created successfully.")


if __name__ == "__main__":
    main()
