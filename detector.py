
import pandas as pd

def detect_suspicious_logins(df, threshold=5, window_minutes=5):

    failed = df[
        df["status"].str.lower() == "failed"
    ].copy()

    alerts = []

    for ip, group in failed.groupby("source_ip"):

        times = group["timestamp"].sort_values().reset_index(drop=True)

        for current_time in times:

            window_start = current_time - pd.Timedelta(
                minutes=window_minutes
            )

            recent_attempts = times[
                (times >= window_start) &
                (times <= current_time)
            ]

            if len(recent_attempts) >= threshold:

                alerts.append({
                    "source_ip": ip,
                    "failed_attempts": len(recent_attempts),
                    "window_start": window_start,
                    "window_end": current_time,
                    "severity": "High"
                })

                break

    return pd.DataFrame(alerts)
