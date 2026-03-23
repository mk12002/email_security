import json
import os
import subprocess
import sys
from pathlib import Path

import numpy as np
import pandas as pd

def _install_ember_module():
    """Install the official lief/ember module required to vectorize the raw JSONL."""
    try:
        import ember
        return
    except ImportError:
        print("Installing the `ember` module from elasticity repository...")
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", 
            "git+https://github.com/elastic/ember.git"
        ])
        
def convert_ember_jsonl_to_parquet(ember_dir: Path, output_parquet: Path):
    """
    Parses EMBER JSONL raw features, converts them to the 2381-vector space
    using the official EMBER vectorizer, and stores them in a highly-compressed Parquet.
    """
    _install_ember_module()
    import ember
    
    ember_dir_str = str(ember_dir)
    print(f"Creating vectorized features from JSONL in {ember_dir_str}...")
    
    # ember.create_vectorized_features parses JSONL and creates X_train.dat, y_train.dat
    # It takes a while and creates numpy memmaps.
    try:
        if not (ember_dir / "X_train.dat").exists():
            ember.create_vectorized_features(ember_dir_str)
    except Exception as e:
        print(f"Failed during ember.create_vectorized_features: {e}")
        raise

    print("Loading vectorized features into memory...")
    # read_vectorized_features returns X (features), y (labels)
    try:
        X_train, y_train = ember.read_vectorized_features(ember_dir_str, subset="train")
    except Exception as e:
        print(f"Failed to read vectorized features: {e}")
        # Sometimes subset="train" is not needed or it's just read_vectorized_features(ember_dir_str)
        try:
            X_train, y_train = ember.read_vectorized_features(ember_dir_str)
        except Exception as e2:
             print(f"Fallback read failed too: {e2}")
             raise

    print(f"Total shape of EMBER training data: {X_train.shape}")
    
    # Filter out unlabeled (-1)
    valid_idx = np.where(y_train != -1)[0]
    X_train = X_train[valid_idx]
    y_train = y_train[valid_idx]
    
    print(f"Shape after removing unlabeled samples: {X_train.shape}")

    # Convert to DataFrame
    print("Building pandas DataFrame for Parquet export...")
    # Because 2381 columns taking float32 is huge, we specify dtype explicitly
    df = pd.DataFrame(X_train, dtype=np.float32)
    df["label"] = y_train.astype(np.int8)
    
    print(f"Saving Parquet to {output_parquet}...")
    df.to_parquet(output_parquet, engine="pyarrow", compression="snappy")
    print("EMBER Parquet conversion completed successfully!")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", type=str, required=True, help="Directory containing train_features_X.jsonl")
    parser.add_argument("--out", type=str, required=True, help="Output parquet file path")
    args = parser.parse_args()
    
    convert_ember_jsonl_to_parquet(Path(args.dir), Path(args.out))
