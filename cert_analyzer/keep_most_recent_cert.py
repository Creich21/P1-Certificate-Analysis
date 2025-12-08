import os
import json
from datetime import datetime

INPUT_DIR = "./data/netlas_certs_blocked_no_duplicates"  


def parse_iso(ts: str) -> datetime:
    """Parse ISO 8601 string with trailing 'Z' into datetime."""
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def get_timestamp(entry):
    """Safely get the timestamp string or return None."""
    try:
        return entry["data"]["timestamp"]
    except (KeyError, TypeError):
        return None
    

def keep_only_latest_in_file(path: str) -> None:
    new_folder = os.path.join(os.path.dirname(path), "most_recents")
    os.makedirs(new_folder, exist_ok=True)
    new_file_path = os.path.join(new_folder, os.path.basename(path))

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list) or not data:
        print(f"{path}: not a non-empty list, writing as-is to {new_file_path}")
        with open(new_file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return

    # filter out entries without a valid timestamp
    valid_entries = [e for e in data if get_timestamp(e) is not None]

    if not valid_entries:
        print(f"{path}: no entries with data.timestamp, writing original data to {new_file_path}")
        with open(new_file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return

    # pick latest among valid entries
    latest_entry = max(
        valid_entries,
        key=lambda e: parse_iso(get_timestamp(e))
    )

    print(f"{new_file_path}: latest timestamp is {get_timestamp(latest_entry)}")

    # write only latest
    with open(new_file_path, "w", encoding="utf-8") as f:
        json.dump([latest_entry], f, indent=2)


def main():
    for filename in os.listdir(INPUT_DIR):
        if not filename.endswith(".json"):
            continue
        filepath = os.path.join(INPUT_DIR, filename)
        keep_only_latest_in_file(filepath)


if __name__ == "__main__":
    main()
