import json
import warnings
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.base import clone
from sklearn.ensemble import RandomForestClassifier
from sklearn.exceptions import ConvergenceWarning
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    auc,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import StratifiedKFold, StratifiedShuffleSplit, train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import LinearSVC

try:
    from xgboost import XGBClassifier
except Exception:
    XGBClassifier = None

try:
    from lightgbm import LGBMClassifier
except Exception:
    LGBMClassifier = None

warnings.filterwarnings("ignore", category=ConvergenceWarning)
warnings.filterwarnings("ignore", category=UserWarning)

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data" / "datasets_fnl"
OUT_DIR = ROOT / "results_new_dataset"
TABLE_DIR = OUT_DIR / "tables"
FIG_DIR = OUT_DIR / "figures"
ALL_FIG_DIR = OUT_DIR / "all_figures"

YEARS = list(range(2016, 2024))
TRAIN_YEARS = [2016, 2017, 2018, 2019]
TEST_YEARS = [2020, 2021, 2022, 2023]
TRACKS = ["static", "dynamic", "fusion_early"]
TRACK_TO_DIR = {"static": "static", "dynamic": "dynamic", "fusion_early": "fusion"}
RANDOM_STATE = 42

def ensure_dirs():
    for p in [TABLE_DIR, FIG_DIR, ALL_FIG_DIR]:
        p.mkdir(parents=True, exist_ok=True)

def model_defs(track):
    models = {
        "RF": RandomForestClassifier(
            n_estimators=250, max_depth=None, min_samples_leaf=1,
            n_jobs=-1, random_state=RANDOM_STATE, class_weight="balanced"
        ),
        "XGB": None,
        "LR": make_pipeline(
            StandardScaler(),
            LogisticRegression(max_iter=3000, class_weight="balanced")
        ),
        "LinearSVM": make_pipeline(
            StandardScaler(),
            LinearSVC(max_iter=6000, class_weight="balanced", dual="auto")
        ),
    }
    if XGBClassifier is not None:
        models["XGB"] = XGBClassifier(
            n_estimators=160, max_depth=4, learning_rate=0.05,
            subsample=0.9, colsample_bytree=0.9, eval_metric="logloss",
            n_jobs=-1, random_state=RANDOM_STATE
        )
    if track == "static":
        if LGBMClassifier is not None:
            models["LGBM"] = LGBMClassifier(
                n_estimators=160, learning_rate=0.05, num_leaves=31,
                random_state=RANDOM_STATE, n_jobs=-1, verbose=-1
            )
        models["MLP"] = make_pipeline(
            StandardScaler(),
            MLPClassifier(
                hidden_layer_sizes=(96, 32), max_iter=500,
                early_stopping=True, random_state=RANDOM_STATE
            )
        )
    return {k: v for k, v in models.items() if v is not None}

def load_df(track, years):
    frames = []
    base = TRACK_TO_DIR.get(track, track)
    for year in years:
        df = pd.read_parquet(DATA_DIR / base / f"{year}.parquet")
        df = df.copy()
        df["sha256"] = df["sha256"].astype(str).str.lower()
        frames.append(df)
    return pd.concat(frames, ignore_index=True)

def split_xy(df, features=None):
    if features is None:
        features = [c for c in df.columns if c not in {"sha256", "label", "year"}]
    x = df[features].replace([np.inf, -np.inf], np.nan).fillna(0)
    y = df["label"].astype(int)
    return x, y, features

def decision_scores(model, x):
    if hasattr(model, "predict_proba"):
        return model.predict_proba(x)[:, 1]
    if hasattr(model, "decision_function"):
        s = model.decision_function(x)
        return 1 / (1 + np.exp(-np.clip(s, -50, 50)))
    return model.predict(x)

def eval_model(model, x_train, y_train, x_test, y_test, sample_weight=None):
    m = clone(model)
    if sample_weight is not None:
        try:
            m.fit(x_train, y_train, sample_weight=sample_weight)
        except (TypeError, ValueError):
            m.fit(x_train, y_train)
    else:
        m.fit(x_train, y_train)
    pred = m.predict(x_test)
    score = decision_scores(m, x_test)
    return {
        "f1": f1_score(y_test, pred, zero_division=0),
        "precision": precision_score(y_test, pred, zero_division=0),
        "recall": recall_score(y_test, pred, zero_division=0),
        "auc": roc_auc_score(y_test, score) if len(np.unique(y_test)) == 2 else np.nan,
        "pred": pred,
        "score": score,
        "model": m,
    }

def save_csv(rows, rel):
    p = TABLE_DIR / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_csv(p, index=False)
    return p

def save_json(obj, rel):
    p = TABLE_DIR / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2), encoding="utf-8")
    return p

def save_fig(name):
    out = FIG_DIR / name
    all_out = ALL_FIG_DIR / name
    out.parent.mkdir(parents=True, exist_ok=True)
    all_out.parent.mkdir(parents=True, exist_ok=True)
    plt.tight_layout()
    plt.savefig(out, dpi=180, bbox_inches="tight")
    plt.savefig(all_out, dpi=180, bbox_inches="tight")
    plt.close()

def plot_bar(df, name, title, x="track", hue="model"):
    plt.figure(figsize=(11, 5))
    sns.barplot(data=df, x=x, y="f1", hue=hue)
    plt.ylim(0, 1.02)
    plt.title(title)
    save_fig(name)

def plot_heatmap(df, name, title, index="track", columns="model"):
    piv = df.pivot_table(index=index, columns=columns, values="f1", aggfunc="max")
    plt.figure(figsize=(9, 5))
    sns.heatmap(piv, annot=True, fmt=".3f", cmap="viridis", vmin=0, vmax=1)
    plt.title(title)
    save_fig(name)

def run_d1():
    rows, curves, cms = [], {}, {}
    for track in TRACKS:
        train_df = load_df(track, TRAIN_YEARS)
        test_df = load_df(track, TEST_YEARS)
        x_tr, y_tr, feats = split_xy(train_df)
        x_te, y_te, _ = split_xy(test_df, feats)
        for name, model in model_defs(track).items():
            r = eval_model(model, x_tr, y_tr, x_te, y_te)
            rows.append({"track": track, "model": name, **{k: r[k] for k in ["f1", "precision", "recall", "auc"]}})
            curves[(track, name)] = (y_te.to_numpy(), r["score"])
            cms[(track, name)] = confusion_matrix(y_te, r["pred"])

    fu_train = load_df("fusion_early", TRAIN_YEARS)
    fu_test = load_df("fusion_early", TEST_YEARS)
    static_train = load_df("static", TRAIN_YEARS)
    dynamic_train = load_df("dynamic", TRAIN_YEARS)
    static_features = [c for c in load_df("static", [2016]).columns if c not in {"sha256", "label", "year"}]
    dynamic_features = [c for c in load_df("dynamic", [2016]).columns if c not in {"sha256", "label", "year"}]
    for name in ["RF", "XGB", "LR", "LinearSVM"]:
        sm = model_defs("static").get(name)
        dm = model_defs("dynamic").get(name)
        if sm is None or dm is None:
            continue
        xs_tr, ys_tr, _ = split_xy(static_train, static_features)
        xd_tr, yd_tr, _ = split_xy(dynamic_train, dynamic_features)
        xs_te, y_te, _ = split_xy(fu_test, static_features)
        xd_te, _, _ = split_xy(fu_test, dynamic_features)
        sm = clone(sm).fit(xs_tr, ys_tr)
        dm = clone(dm).fit(xd_tr, yd_tr)
        score = (decision_scores(sm, xs_te) + decision_scores(dm, xd_te)) / 2
        pred = (score >= 0.5).astype(int)
        rows.append({
            "track": "fusion_late", "model": name,
            "f1": f1_score(y_te, pred, zero_division=0),
            "precision": precision_score(y_te, pred, zero_division=0),
            "recall": recall_score(y_te, pred, zero_division=0),
            "auc": roc_auc_score(y_te, score),
        })
        curves[("fusion_late", name)] = (y_te.to_numpy(), score)
        cms[("fusion_late", name)] = confusion_matrix(y_te, pred)

    df = pd.DataFrame(rows)
    save_csv(rows, "d1_temporal_split/summary.csv")
    save_json(df.to_dict(orient="records"), "d1_temporal_split/metrics.json")
    plot_bar(df, "d1_bar_track_model.png", "D1 Temporal Split - F1")
    plot_heatmap(df, "d1_heatmap_f1.png", "D1 Temporal Split - Best F1")

    for track in ["static", "dynamic", "fusion_early", "fusion_late"]:
        subset = df[df.track == track].sort_values("f1", ascending=False)
        if subset.empty:
            continue
        best_model = subset.iloc[0]["model"]
        y_true, score = curves[(track, best_model)]
        fpr, tpr, _ = roc_curve(y_true, score)
        prec, rec, _ = precision_recall_curve(y_true, score)
        plt.figure(figsize=(6, 5))
        plt.plot(fpr, tpr, label=f"AUC={auc(fpr, tpr):.3f}")
        plt.plot([0, 1], [0, 1], "--", color="gray")
        plt.title(f"D1 ROC - {track} / {best_model}")
        plt.xlabel("False Positive Rate")
        plt.ylabel("True Positive Rate")
        plt.legend()
        save_fig(f"d1_roc_{track}.png")

        plt.figure(figsize=(6, 5))
        plt.plot(rec, prec)
        plt.title(f"D1 Precision-Recall - {track} / {best_model}")
        plt.xlabel("Recall")
        plt.ylabel("Precision")
        save_fig(f"d1_pr_{track}.png")

        plt.figure(figsize=(4.8, 4))
        sns.heatmap(cms[(track, best_model)], annot=True, fmt="d", cmap="Blues")
        plt.title(f"D1 Confusion Matrix - {track} / {best_model}")
        plt.xlabel("Predicted")
        plt.ylabel("Actual")
        save_fig(f"d1_cm_{track}.png")
    return df

def run_d4():
    rows = []
    for track in TRACKS:
        for year in YEARS:
            df = load_df(track, [year])
            x, y, feats = split_xy(df)
            tr, te = train_test_split(
                np.arange(len(df)), test_size=0.2, stratify=y, random_state=RANDOM_STATE
            )
            for name, model in model_defs(track).items():
                r = eval_model(model, x.iloc[tr], y.iloc[tr], x.iloc[te], y.iloc[te])
                rows.append({"track": track, "year": year, "model": name, **{k: r[k] for k in ["f1", "precision", "recall", "auc"]}})
    df = pd.DataFrame(rows)
    save_csv(rows, "d4_same_year/summary.csv")
    save_json(df.to_dict(orient="records"), "d4_same_year/metrics.json")
    plot_bar(df.groupby(["track", "model"], as_index=False)["f1"].mean(), "d4_bar_all.png", "D4 Same-Year Mean F1")
    for track in TRACKS:
        plot_heatmap(df[df.track == track], f"d4_heatmap_{track}.png", f"D4 Same-Year F1 - {track}", index="year")
        plt.figure(figsize=(9, 5))
        sns.lineplot(data=df[df.track == track], x="year", y="f1", hue="model", marker="o")
        plt.ylim(0, 1.02)
        plt.title(f"D4 F1 Trend - {track}")
        save_fig(f"d4_f1_trend_{track}.png")
    return df

def run_d2():
    rows = []
    for track in TRACKS:
        for mode in ["cumulative", "sliding_w2"]:
            for test_year in YEARS[1:]:
                train_years = [y for y in YEARS if y < test_year] if mode == "cumulative" else [y for y in [test_year - 2, test_year - 1] if y in YEARS]
                if not train_years:
                    continue
                train_df = load_df(track, train_years)
                test_df = load_df(track, [test_year])
                x_tr, y_tr, feats = split_xy(train_df)
                x_te, y_te, _ = split_xy(test_df, feats)
                for name, model in model_defs(track).items():
                    r = eval_model(model, x_tr, y_tr, x_te, y_te)
                    rows.append({
                        "track": track, "mode": mode, "train_years": "+".join(map(str, train_years)),
                        "test_year": test_year, "model": name,
                        **{k: r[k] for k in ["f1", "precision", "recall", "auc"]},
                    })
    df = pd.DataFrame(rows)
    save_csv(rows, "d2_sliding_window/summary.csv")
    save_json(df.to_dict(orient="records"), "d2_sliding_window/metrics.json")
    for track in TRACKS:
        for mode in ["cumulative", "sliding_w2"]:
            sub = df[(df.track == track) & (df["mode"] == mode)]
            if sub.empty:
                continue
            plt.figure(figsize=(9, 5))
            sns.lineplot(data=sub, x="test_year", y="f1", hue="model", marker="o")
            plt.ylim(0, 1.02)
            plt.title(f"D2 {mode} F1 - {track}")
            save_fig(f"d2_{mode}_{track}_f1_trend.png")
        plot_heatmap(df[df.track == track], f"d2_heatmap_{track}.png", f"D2 F1 - {track}", index="test_year")
    return df

def feature_groups(features):
    groups = {
        "permissions": [c for c in features if c.startswith("perm_")],
        "api_calls": [c for c in features if c.startswith("api_")],
        "reflection": [c for c in features if "reflect" in c.lower()],
        "dex": [c for c in features if "dex" in c.lower()],
        "anti_analysis": [c for c in features if any(k in c.lower() for k in ["emulator", "root", "debug", "hook", "frida"])],
        "manifest": [c for c in features if c.startswith("manifest_")],
        "network": [c for c in features if c.startswith("net_") or "network" in c.lower() or "dns" in c.lower() or "host" in c.lower()],
        "file_info": [c for c in features if "file" in c.lower() or "size" in c.lower()],
        "crypto": [c for c in features if "crypto" in c.lower()],
        "code_load": [c for c in features if any(k in c.lower() for k in ["load", "loader", "native"])],
        "data_exfil": [c for c in features if any(k in c.lower() for k in ["sms", "contact", "call_log", "location"])],
        "system": [c for c in features if any(k in c.lower() for k in ["system", "exec", "runtime", "device", "package"])],
    }
    return {k: list(dict.fromkeys(v)) for k, v in groups.items() if v}

def run_d3():
    rows = []
    train_df = {t: load_df(t, TRAIN_YEARS) for t in TRACKS}
    test_df = {t: load_df(t, TEST_YEARS) for t in TRACKS}
    for track in TRACKS:
        x_tr, y_tr, feats = split_xy(train_df[track])
        x_te, y_te, _ = split_xy(test_df[track], feats)
        groups = feature_groups(feats)
        for name in ["RF", "XGB"]:
            model = model_defs(track).get(name)
            if model is None:
                continue
            base = eval_model(model, x_tr, y_tr, x_te, y_te)
            rows.append({"track": track, "mode": "leave_one_out", "group": "BASELINE", "model": name, "n_features": len(feats), **{k: base[k] for k in ["f1", "precision", "recall", "auc"]}, "label": "", "group_size": np.nan})
            for g, cols in groups.items():
                keep = [c for c in feats if c not in cols]
                if len(keep) < 2:
                    continue
                r = eval_model(model, x_tr[keep], y_tr, x_te[keep], y_te)
                rows.append({"track": track, "mode": "leave_one_out", "group": g, "model": name, "n_features": len(keep), **{k: r[k] for k in ["f1", "precision", "recall", "auc"]}, "label": f"excl_{g}", "group_size": len(cols)})
                r = eval_model(model, x_tr[cols], y_tr, x_te[cols], y_te)
                rows.append({"track": track, "mode": "single_group", "group": g, "model": name, "n_features": len(cols), **{k: r[k] for k in ["f1", "precision", "recall", "auc"]}, "label": f"only_{g}", "group_size": len(cols)})
    df = pd.DataFrame(rows)
    save_csv(rows, "d3_feature_ablation/summary.csv")
    save_json(df.to_dict(orient="records"), "d3_feature_ablation/metrics.json")
    for track in TRACKS:
        for mode in ["leave_one_out", "single_group"]:
            sub = df[(df.track == track) & (df["mode"] == mode) & (df.group != "BASELINE")]
            if sub.empty:
                continue
            plt.figure(figsize=(12, 6))
            sns.barplot(data=sub, x="group", y="f1", hue="model")
            plt.xticks(rotation=35, ha="right")
            plt.ylim(0, 1.02)
            plt.title(f"D3 {mode} - {track}")
            save_fig(f"d3_{mode}_{track}.png")
    return df

def run_d5():
    rows = []
    decay_values = [1.0, 0.9, 0.75, 0.5]
    for track in TRACKS:
        train_df = load_df(track, TRAIN_YEARS)
        test_df = load_df(track, TEST_YEARS)
        x_tr, y_tr, feats = split_xy(train_df)
        x_te, y_te, _ = split_xy(test_df, feats)
        max_year = train_df["year"].max()
        for decay in decay_values:
            weights = decay ** (max_year - train_df["year"].to_numpy())
            for name, model in model_defs(track).items():
                r = eval_model(model, x_tr, y_tr, x_te, y_te, sample_weight=weights)
                rows.append({"track": track, "decay": decay, "model": name, **{k: r[k] for k in ["f1", "precision", "recall", "auc"]}})
    df = pd.DataFrame(rows)
    save_csv(rows, "d5_time_weighted/summary.csv")
    for track in TRACKS:
        plt.figure(figsize=(9, 5))
        sns.lineplot(data=df[df.track == track], x="decay", y="f1", hue="model", marker="o")
        plt.ylim(0, 1.02)
        plt.title(f"D5 Time Weighted F1 - {track}")
        save_fig(f"d5_time_weighted_{track}.png")
    return df

def run_d6():
    rows = []
    for track in TRACKS:
        df = load_df(track, YEARS)
        x, y, feats = split_xy(df)
        tr, te = train_test_split(np.arange(len(df)), test_size=0.25, stratify=y, random_state=RANDOM_STATE)
        for name, model in model_defs(track).items():
            r = eval_model(model, x.iloc[tr], y.iloc[tr], x.iloc[te], y.iloc[te])
            rows.append({"track": track, "model": name, **{k: r[k] for k in ["f1", "precision", "recall", "auc"]}})
    df = pd.DataFrame(rows)
    save_csv(rows, "d6_random_split/summary.csv")
    plot_bar(df, "d6_random_split_bar.png", "D6 Random Split - F1")
    plot_heatmap(df, "d6_random_split_heatmap.png", "D6 Random Split - F1")
    return df

def run_learning_curves():
    rows = []
    fractions = [0.2, 0.4, 0.6, 0.8, 1.0]
    for track in TRACKS:
        train_df = load_df(track, TRAIN_YEARS)
        test_df = load_df(track, TEST_YEARS)
        x_all, y_all, feats = split_xy(train_df)
        x_te, y_te, _ = split_xy(test_df, feats)
        for frac in fractions:
            if frac < 1:
                splitter = StratifiedShuffleSplit(n_splits=1, train_size=frac, random_state=RANDOM_STATE)
                idx, _ = next(splitter.split(x_all, y_all))
            else:
                idx = np.arange(len(train_df))
            for name in ["RF", "XGB"]:
                model = model_defs(track).get(name)
                if model is None:
                    continue
                r = eval_model(model, x_all.iloc[idx], y_all.iloc[idx], x_te, y_te)
                rows.append({"track": track, "train_fraction": frac, "train_rows": len(idx), "model": name, **{k: r[k] for k in ["f1", "precision", "recall", "auc"]}})
    df = pd.DataFrame(rows)
    save_csv(rows, "learning_curves/summary.csv")
    for track in TRACKS:
        plt.figure(figsize=(8, 5))
        sns.lineplot(data=df[df.track == track], x="train_fraction", y="f1", hue="model", marker="o")
        plt.ylim(0, 1.02)
        plt.title(f"Learning Curve - {track}")
        save_fig(f"learning_curve_{track}.png")
    return df

def run_phase2(d1_df):
    rows = []
    for track in TRACKS:
        train_df = load_df(track, TRAIN_YEARS)
        test_df = load_df(track, TEST_YEARS)
        x_tr, y_tr, feats = split_xy(train_df)
        x_te, y_te, _ = split_xy(test_df, feats)
        rf = model_defs(track)["RF"]
        rf_fit = clone(rf).fit(x_tr, y_tr)
        importances = getattr(rf_fit, "feature_importances_", np.ones(len(feats)) / len(feats))
        order = np.argsort(importances)[::-1]
        csum = np.cumsum(importances[order]) / max(importances.sum(), 1e-12)
        for mode, n in [("top_30", min(30, len(feats))), ("auto_95pct", int(np.searchsorted(csum, 0.95) + 1))]:
            selected = [feats[i] for i in order[:n]]
            for name in ["RF", "XGB"]:
                model = model_defs(track).get(name)
                if model is None:
                    continue
                r = eval_model(model, x_tr[selected], y_tr, x_te[selected], y_te)
                rows.append({"experiment": mode, "track": track, "model": name, "n_features": len(selected), **{k: r[k] for k in ["f1", "precision", "recall", "auc"]}})
    df = pd.DataFrame(rows)
    for exp in ["top_30", "auto_95pct"]:
        sub = df[df.experiment == exp]
        save_csv(sub.to_dict(orient="records"), f"phase2/{exp}/summary.csv")
    plot_bar(df, "phase2_feature_selection_bar.png", "Phase 2 Feature Selection - F1", x="track", hue="experiment")
    return df

def run_drift_matrix(d4_df):
    rows = []
    for track in TRACKS:
        for train_year in YEARS:
            train_df = load_df(track, [train_year])
            x_tr, y_tr, feats = split_xy(train_df)
            for test_year in YEARS:
                test_df = load_df(track, [test_year])
                x_te, y_te, _ = split_xy(test_df, feats)
                r = eval_model(model_defs(track)["RF"], x_tr, y_tr, x_te, y_te)
                rows.append({"track": track, "train_year": train_year, "test_year": test_year, "model": "RF", **{k: r[k] for k in ["f1", "precision", "recall", "auc"]}})
    df = pd.DataFrame(rows)
    save_csv(rows, "drift_matrix/summary.csv")
    for track in TRACKS:
        plot_heatmap(df[df.track == track], f"drift_matrix_{track}.png", f"RF Drift Matrix - {track}", index="train_year", columns="test_year")
    return df

def run_master_summary(named_frames):
    best_rows = []
    for exp, df in named_frames.items():
        if df is None or df.empty or "f1" not in df.columns:
            continue
        group_cols = [c for c in ["track", "mode", "experiment"] if c in df.columns]
        for _, sub in df.groupby(group_cols or [lambda _: "all"]):
            best = sub.sort_values("f1", ascending=False).iloc[0].to_dict()
            best["source_experiment"] = exp
            best_rows.append(best)
    master = pd.DataFrame(best_rows)
    save_csv(master.to_dict(orient="records"), "master_summary/best_per_experiment.csv")
    save_csv(master.sort_values("f1", ascending=False).to_dict(orient="records"), "master_summary/full_master_table.csv")
    plt.figure(figsize=(12, 6))
    sns.barplot(data=master, x="source_experiment", y="f1", hue="track")
    plt.xticks(rotation=30, ha="right")
    plt.ylim(0, 1.02)
    plt.title("Best F1 Per Experiment")
    save_fig("master_best_per_experiment.png")
    return master

def main():
    ensure_dirs()
    print(f"Output: {OUT_DIR}")
    print("Running D1 temporal split...")
    d1 = run_d1()
    print("Running D4 same-year baseline...")
    d4 = run_d4()
    print("Running D2 sliding/cumulative...")
    d2 = run_d2()
    print("Running D3 feature ablation...")
    d3 = run_d3()
    print("Running D5 time-weighted...")
    d5 = run_d5()
    print("Running D6 random split...")
    d6 = run_d6()
    print("Running drift matrix...")
    drift = run_drift_matrix(d4)
    print("Running learning curves...")
    lc = run_learning_curves()
    print("Running phase 2 feature selection...")
    phase2 = run_phase2(d1)
    print("Writing master summary...")
    run_master_summary({
        "d1_temporal_split": d1,
        "d4_same_year": d4,
        "d2_sliding_window": d2,
        "d3_feature_ablation": d3,
        "d5_time_weighted": d5,
        "d6_random_split": d6,
        "drift_matrix": drift,
        "learning_curves": lc,
        "phase2": phase2,
    })
    print("Done.")

if __name__ == "__main__":
    main()
