import re
import sys

# --- Extract title from a BibTeX entry ---
def extract_title(entry_text):
    match = re.search(
        r'title\s*=\s*[{"]\s*(.*?)\s*["}]',
        entry_text,
        re.IGNORECASE | re.DOTALL
    )
    if match:
        title = match.group(1).strip()
        title = re.sub(r'\s+', ' ', title.replace('\n', ' '))  # clean whitespace
        return title
    return None


# --- Normalize title for comparison ---
def normalize_title(title):
    """Lowercase and remove punctuation for better duplicate detection."""
    t = title.lower()
    t = re.sub(r'[^a-z0-9\s]', '', t)
    t = re.sub(r'\s+', ' ', t).strip()
    return t


# --- Split a BibTeX file into entries ---
def split_entries(content):
    entries = re.split(r'(?=@\w+)', content)
    return [e.strip() for e in entries if e.strip()]


# --- Check and remove duplicate titles ---
def remove_duplicate_titles(bib_path, output_path):
    with open(bib_path, 'r', encoding='utf-8') as f:
        content = f.read()

    entries = split_entries(content)
    title_map = {}
    unique_entries = []
    duplicates = []

    for entry in entries:
        title = extract_title(entry)
        if not title:
            # No title — keep it (we can’t deduplicate it)
            unique_entries.append(entry)
            continue

        norm = normalize_title(title)
        if norm in title_map:
            duplicates.append(title)
        else:
            title_map[norm] = title
            unique_entries.append(entry)

    # --- Write deduplicated entries ---
    with open(output_path, 'w', encoding='utf-8') as f:
        for entry in unique_entries:
            f.write(entry.strip() + "\n\n")

    print(f"\n -------------- Checking for duplicate Titles in {bib_path} --------------")
    print(f"\n📚 File processed: {bib_path}")
    print(f"📄 Total entries before: {len(entries)}")
    print(f"✅ Unique titles kept: {len(unique_entries)}")
    print(f"🗑️  Duplicates removed: {len(duplicates)}")

    if duplicates:
        print("\n⚠️ Duplicate Titles Removed:")
        for i, t in enumerate(duplicates, 1):
            print(f"  {i}. {t}")
        print("\n💾 Cleaned file saved as:", output_path)
    else:
        print("\n✅ No duplicate titles found!")
        print("\n💾 Output file:", output_path)



# --- Run from command line ---
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python check_titles.py <input_file.bib> [output_file.bib]")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = "final.bib"

    remove_duplicate_titles(input_file, output_file)
