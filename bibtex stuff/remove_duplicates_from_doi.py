import re
import glob
from remove_duplicate_titles import remove_duplicate_titles

# --- Extract DOI from one BibTeX entry ---
def extract_doi(entry_text):
    match = re.search(
        r'doi\s*=\s*[{"]?\s*([^}",\s]+)\s*["}]?',
        entry_text,
        re.IGNORECASE
    )
    if match:
        return match.group(1).strip().lower()
    return None


# --- Extract title from one BibTeX entry (optional, for reporting) ---
def extract_title(entry_text):
    match = re.search(
        r'title\s*=\s*[{"]\s*(.*?)\s*["}]',
        entry_text,
        re.IGNORECASE | re.DOTALL
    )
    if match:
        # Clean up whitespace and LaTeX braces
        return re.sub(r'\s+', ' ', match.group(1).strip().replace('\n', ' '))
    return "(No Title Found)"


# --- Extract DOIs and full entries from a single BibTeX file ---
def extract_entries_from_bibtex(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Split entries by '@' but keep the '@' for clarity
    entries = re.split(r'(?=@\w+)', content)
    entries = [e.strip() for e in entries if e.strip()]  # remove empties

    doi_entry_map = {}
    no_doi_entries = []
    duplicate_entries = []  # (doi, title) for reporting

    for entry in entries:
        doi = extract_doi(entry)
        title = extract_title(entry)
        if doi:
            if doi not in doi_entry_map:
                doi_entry_map[doi] = entry
            else:
                duplicate_entries.append((doi, title))
        else:
            no_doi_entries.append(entry)

    return doi_entry_map, no_doi_entries, duplicate_entries


# --- Combine multiple BibTeX files ---
def merge_bibtex_files(file_paths):
    merged_dois = {}
    merged_no_doi = []
    all_duplicates = []

    for file_path in file_paths:
        print(f"📚 Processing: {file_path}")
        doi_entry_map, no_doi_entries, duplicates = extract_entries_from_bibtex(file_path)

        for doi, entry in doi_entry_map.items():
            if doi not in merged_dois:
                merged_dois[doi] = entry
            else:
                # Track duplicates found across multiple files
                title = extract_title(entry)
                all_duplicates.append((doi, title))

        merged_no_doi.extend(no_doi_entries)
        all_duplicates.extend(duplicates)

    return merged_dois, merged_no_doi, all_duplicates


# --- Save unique BibTeX entries to new file ---
def save_unique_entries(doi_entry_map, no_doi_entries, output_path):
    with open(output_path, 'w', encoding='utf-8') as f:
        for entry in doi_entry_map.values():
            f.write(entry.strip() + "\n\n")

        for entry in no_doi_entries:
            f.write(entry.strip() + "\n\n")

    print(f"✅ Saved {len(doi_entry_map)} unique DOI entries "
          f"+ {len(no_doi_entries)} entries without DOI "
          f"→ {output_path}")


# --- Example usage ---
if __name__ == "__main__":
    # Option 1: manually list BibTeX files
    bib_files = [
        "acm.bib",
        "ieee.bib",
        "scopus.bib",
        "webofscience.bib"
    
    ]

    # Option 2: automatically include all .bib files in current folder
    # bib_files = glob.glob("*.bib")

    output_file = "merged_unique.bib"

    merged_dois, merged_no_doi, duplicates = merge_bibtex_files(bib_files)

    print(f"\n📊 Total unique DOIs: {len(merged_dois)}")
    print(f"📄 Entries without DOI: {len(merged_no_doi)}")

    if duplicates:
        print(f"\n⚠️  Total papers removed due to duplicate DOIs: {len(duplicates)}")
        for doi, title in duplicates:
            print(f"   - {title} (DOI: {doi})")
    else:
        print("\n✅ No duplicate DOIs found!")

    save_unique_entries(merged_dois, merged_no_doi, output_file)

    remove_duplicate_titles(output_file,"final.bib")











