from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from detections import detect_attacks
from severity import calculate_severity
from mitre_mapper import map_mitre
from live_events import live_events
from analyzer import analyze_logs

import time
import os
from datetime import datetime


class LogHandler(FileSystemEventHandler):

    def on_modified(self, event):

        if event.is_directory:
            return

        if event.src_path.endswith(".log"):
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            print("\n================================================")
            print(" 🚨 LIVE SOC ALERT DETECTED ")
            print("================================================")
            print(f"📁 File: {event.src_path}")
            print(f"⏰ Time: {current_time}")

            try:

                with open(event.src_path, "r", encoding="utf-8", errors="ignore") as file:

                    logs = file.readlines()

                    latest_logs = logs[-5:]
                    print("\n📜 Latest Security Events:\n")
                    for index, log in enumerate(latest_logs, start=1):

                        clean_log = log.strip()
                        if not clean_log:
                            continue

                        print(f"🧾 Event #{index}")
                        print(f"➡️ Log: {clean_log}")

                        detections = detect_attacks(clean_log)

                        severity = calculate_severity(clean_log)

                        mitre = map_mitre(clean_log)
                        # Generate AI explanation
                        ai_summary = analyze_logs(clean_log)

                        # Store live SOC event
                        event_data = {
                            "time": current_time,
                            "log": clean_log,
                            "severity": severity,
                            "detections": detections,
                            "mitre": mitre,
                            "ai_summary": ai_summary
                        }

                        live_events.append(event_data)

                        print(f"⚠️ Severity: {severity}")

                        if detections:

                            print(f"🚨 Detections: {', '.join(detections)}")

                        else:

                            print("✅ No known threats detected")

                        if mitre:

                            print("🎯 MITRE ATT&CK Techniques:")

                            for technique in mitre:

                                print(
                                    f"   - {technique['Technique']} : {technique['Name']}"
                                )
                        print("🤖 AI Threat Analysis:")
                        print(ai_summary)

                        print("------------------------------------------------")

                    print("\n================================================\n")

            except Exception as e:

                print(f"❌ Error processing log file: {str(e)}")


def start_monitoring(path_to_watch):

    event_handler = LogHandler()

    observer = Observer()

    observer.schedule(
        event_handler,
        path=path_to_watch,
        recursive=False
    )

    observer.start()

    print(f"[+] Monitoring started on: {path_to_watch}")

    try:

        while True:
            time.sleep(1)

    except KeyboardInterrupt:

        observer.stop()

    observer.join()


if __name__ == "__main__":

    logs_folder = "./live_logs"

    os.makedirs(
        logs_folder,
        exist_ok=True
    )

    start_monitoring(logs_folder)