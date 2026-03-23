import pandas as pd
import glob

print("Checking processed datasets class distribution:")
for f in glob.glob("../datasets_processed/*.csv"):
    try:
        df = pd.read_csv(f)
        if "label" in df.columns:
            print(f"\n[{f}]")
            print(df["label"].value_counts().to_string())
            print(f"Total Rows: {len(df)}")
    except Exception as e:
        print(f"Error reading {f}: {e}")
