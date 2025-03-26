def load_payloads(payload_type):
    try:
        with open(f"payloads/{payload_type}_payloads.txt", "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        return []
