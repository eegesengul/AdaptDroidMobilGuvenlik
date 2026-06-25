import pandas as pd
import os
import glob
from pathlib import Path

dest_b = Path('data/datasets_fnl')
dest_b.mkdir(parents=True, exist_ok=True)
(dest_b/'static').mkdir(exist_ok=True)
(dest_b/'dynamic').mkdir(exist_ok=True)
(dest_b/'fusion').mkdir(exist_ok=True)

for year in range(2016, 2024):
    yb_stat = glob.glob(f'features_final_training/static_features_benign/{year}/*.parquet')
    ym_stat = glob.glob(f'features_final_training/static_features_malware/{year}/*.parquet')

    if yb_stat and ym_stat:
        df_bs = pd.read_parquet(yb_stat[0])
        df_bs['sha256'] = df_bs['sha256'].str.lower()
        df_bs['label'] = 0
        df_bs['year'] = year

        df_ms = pd.read_parquet(ym_stat[0])
        df_ms['sha256'] = df_ms['sha256'].str.lower()
        df_ms['label'] = 1
        df_ms['year'] = year

        df_stat = pd.concat([df_bs, df_ms], ignore_index=True)
        df_stat.to_parquet(dest_b/'static'/f'{year}.parquet', index=False)

    yb_dyn = glob.glob(f'features_final_training/dynamic_features_benign/{year}/*.parquet')
    ym_dyn = glob.glob(f'features_final_training/dynamic_features_malware/{year}/*.parquet')

    if yb_dyn and ym_dyn:
        df_bd = pd.read_parquet(yb_dyn[0])
        df_bd['label'] = 0
        df_bd['year'] = year
        df_bd['sha256'] = df_bd['sha256'].str.lower()
        
        df_md = pd.read_parquet(ym_dyn[0])
        df_md['label'] = 1
        df_md['year'] = year
        df_md['sha256'] = df_md['sha256'].str.lower()
        
        df_dyn = pd.concat([df_bd, df_md], ignore_index=True)
        drop_cols = ["frida_dex_load", "dex_loader_count", "frida_dex_load_inmemory", "frida_native_lib_load"]
        df_dyn = df_dyn.drop(columns=[c for c in drop_cols if c in df_dyn.columns])
        
        df_dyn.to_parquet(dest_b/'dynamic'/f'{year}.parquet', index=False)
        
        if yb_stat and ym_stat:
            df_bf = pd.merge(df_bs.drop(columns=['label', 'year']), df_bd.drop(columns=[c for c in drop_cols if c in df_bd.columns]), on='sha256', how='inner')
            df_mf = pd.merge(df_ms.drop(columns=['label', 'year']), df_md.drop(columns=[c for c in drop_cols if c in df_md.columns]), on='sha256', how='inner')
            df_fus = pd.concat([df_bf, df_mf], ignore_index=True)
            if df_fus['label'].nunique() < 2:
                print(f"WARNING: fusion/{year}.parquet has labels {df_fus['label'].value_counts().to_dict()}")
            df_fus.to_parquet(dest_b/'fusion'/f'{year}.parquet', index=False)
print("Dataset created successfully in data/datasets_fnl/")
