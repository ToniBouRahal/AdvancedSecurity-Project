import numpy as np
import pandas as pd

OUTPUT_CSV = "dataset.csv"

def generate_synthetic_data():
    np.random.seed(42)

    rows = []

    # ---------- Normal / benign IPs ----------
    # Behave like real users:
    # - few attempts
    # - mostly successful
    # - larger time between attempts
    num_benign_ips = 50

    for i in range(num_benign_ips):
        ip = f"10.0.0.{i+1}"

        # total attempts between 3 and 20
        total_attempts = int(np.random.randint(3, 20))

        # failed attempts small
        failed_attempts = int(np.random.randint(0, min(5, total_attempts)))
        success_attempts = total_attempts - failed_attempts

        success_rate = success_attempts / total_attempts if total_attempts > 0 else 0.0

        # typical user: 1–3 usernames (typos, or 1 per device)
        unique_usernames = int(np.random.randint(1, 4))

        # time between attempts: human speed → 2 to 30 seconds
        min_delta = float(np.random.uniform(2.0, 30.0))

        rows.append({
            "ip": ip,
            "total_attempts": total_attempts,
            "failed_attempts": failed_attempts,
            "success_rate": success_rate,
            "unique_usernames": unique_usernames,
            "min_delta": min_delta,
            "label": 0,   # benign
        })

    # ---------- Attacker IPs ----------
    # Behave like brute-force / credential stuffing:
    # - many attempts
    # - mostly failures
    # - very small time between attempts
    num_attack_ips = 30

    for i in range(num_attack_ips):
        ip = f"192.168.1.{i+1}"

        # attackers hammer: 30–200 attempts
        total_attempts = int(np.random.randint(30, 200))

        # almost all fail, maybe a couple successes
        successes = int(np.random.randint(0, 3))
        failed_attempts = total_attempts - successes
        success_rate = successes / total_attempts if total_attempts > 0 else 0.0

        # credential stuffing: 1–10 usernames from same IP
        unique_usernames = int(np.random.randint(1, 10))

        # very fast attempts: 0.05–0.5 seconds between attempts
        min_delta = float(np.random.uniform(0.05, 0.5))

        rows.append({
            "ip": ip,
            "total_attempts": total_attempts,
            "failed_attempts": failed_attempts,
            "success_rate": success_rate,
            "unique_usernames": unique_usernames,
            "min_delta": min_delta,
            "label": 1,   # attacker
        })

    df = pd.DataFrame(rows)
    df.to_csv(OUTPUT_CSV, index=False)

    print(f"[+] Synthetic dataset generated: {OUTPUT_CSV}")
    print(df.head())
    print()
    print("Class distribution:")
    print(df['label'].value_counts())

if __name__ == "__main__":
    generate_synthetic_data()
