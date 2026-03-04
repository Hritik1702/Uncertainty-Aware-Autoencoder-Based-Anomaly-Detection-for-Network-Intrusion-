import streamlit as st
import pandas as pd
import time

st.set_page_config(page_title="Real-Time IDS", layout="wide")

st.title("Real-Time Intrusion Detection System")
st.caption("Live network monitoring")

placeholder = st.empty()

while True:
    try:
        df = pd.read_csv("ids_output.csv")

        with placeholder.container():
            st.metric("Total Flows", len(df))
            st.metric(
                "Anomalies",
                (df["status"] == "ANOMALY").sum()
            )

            st.dataframe(
                df.tail(10),
                use_container_width=True
            )

        time.sleep(2)

    except FileNotFoundError:
        st.warning("Waiting for IDS output...")
        time.sleep(2)
