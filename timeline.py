import pandas as pd
import streamlit as st


def create_timeline(df):

    possible_time_columns = [
        "timestamp",
        "time",
        "date",
        "@timestamp"
    ]

    timeline_df = df.copy()

    for col in possible_time_columns:

        if col in timeline_df.columns:

            try:
                timeline_df[col] = pd.to_datetime(
                    timeline_df[col],
                    errors="coerce"
                )

                timeline_df = timeline_df.sort_values(by=col)

                return timeline_df

            except Exception:
                pass

    return timeline_df



def display_timeline(timeline_df):

    st.subheader("Attack Timeline")

    if timeline_df.empty:

        st.warning("No timeline data available")

        return

    timeline_display = timeline_df.head(25)

    for index, row in timeline_display.iterrows():

        with st.container(border=True):

            cols = st.columns([1, 4])

            timestamp = "N/A"

            for possible_col in [
                "timestamp",
                "time",
                "date",
                "@timestamp"
            ]:

                if possible_col in row:
                    timestamp = str(row[possible_col])
                    break

            cols[0].markdown(
                f"### ⏱️\n`{timestamp}`"
            )

            cols[1].markdown(
                f"""
### 📌 Event Details
```json
{row.to_dict()}
```
"""
            )