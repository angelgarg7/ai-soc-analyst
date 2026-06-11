import pandas as pd
import json

def parse_logs(uploaded_file):

    if uploaded_file.name.endswith(".csv"):

        df = pd.read_csv(uploaded_file)

    elif uploaded_file.name.endswith(".txt"):

        data = uploaded_file.read().decode("utf-8")

        df = pd.DataFrame(
            data.splitlines(),
            columns=["log"]
        )

    elif uploaded_file.name.endswith(".json"):

        raw_data = uploaded_file.read().decode("utf-8")

        try:

            # Standard JSON
            data = json.loads(raw_data)

        except json.JSONDecodeError:

            # JSON Lines / multiple JSON objects
            data = []

            for line in raw_data.splitlines():

                line = line.strip()

                if line:

                    try:
                            data.append(json.loads(line))

                    except Exception:
                            pass

        if isinstance(data, list):

            df = pd.DataFrame(data)

        elif isinstance(data, dict):

            df = pd.json_normalize(data)

        else:

            df = pd.DataFrame({"data": [str(data)]})

    else:

        df = None

    return df