import glob
import os
from remove_duplicates_from_doi import merge_bibtex_files, save_unique_entries
from remove_duplicate_titles import remove_duplicate_titles

def main():
    # --- Step 1: Define your BibTeX input files ---

# --- Automatically get all .bib files in a folder ---
    bib_folder = "bibtex_files"  # folder containing your .bib files
    bib_files = [f for f in glob.glob(os.path.join(bib_folder, "*.bib")) if os.path.isfile(f)]

    if not bib_files:
        print(f"⚠️ No .bib files found in folder '{bib_folder}'")
    else:
        print(f"📚 Found {len(bib_files)} .bib files in '{bib_folder}':")
        for f in bib_files:
            print(f"   - {f}")


    # --- Step 2: Output paths ---
    doi_output_file = "merged_based_on_doi.bib"
    final_output_file = "final.bib"

    print("\n==================== STEP 1: Removing DOI Duplicates ====================")
    merged_dois, merged_no_doi, duplicates = merge_bibtex_files(bib_files)
    save_unique_entries(merged_dois, merged_no_doi, doi_output_file)


    if duplicates:
        print(f"\n⚠️  Total papers removed due to duplicate DOIs: {len(duplicates)}")
        for doi, title in duplicates:
            print(f"   - {title} (DOI: {doi})")
    else:
        print("\n✅ No duplicate DOIs found!")

    # if duplicates:
    #     print(f"\n⚠️  Found {len(duplicates)} duplicate DOIs (removed).")
    # else:
    #     print("\n✅ No duplicate DOIs found!")

    print("\n==================== STEP 2: Removing Title Duplicates ====================")
    remove_duplicate_titles(doi_output_file, final_output_file)

    print("\n🎯 All done! Final deduplicated BibTeX saved as:", final_output_file)


if __name__ == "__main__":
    main()
