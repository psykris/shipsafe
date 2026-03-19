import csv
import json

# PRI005: PII written to plaintext files without encryption

def export_users(users: list) -> None:
    # PRI005: CSV write with SSN
    with open("users.csv", "w") as f:
        writer = csv.writer(f)
        for user in users:
            writer.writerow([user["name"], user["ssn"], user["email"]])

    # PRI005: JSON dump with credit_card field
    with open("payments.json", "w") as f:
        json.dump({"credit_card": "4111111111111111", "amount": 100}, f)

    # PRI005: direct file write with passport number
    with open("records.txt", "w") as fh:
        fh.write(f"passport_number={users[0]['passport']}")


def save_pii_data(data: dict) -> None:
    # PRI005: save with pii_data variable name
    with open("export.json", "w") as f:
        f.write(json.dumps(data))
