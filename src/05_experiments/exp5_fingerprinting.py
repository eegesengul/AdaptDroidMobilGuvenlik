"""
Deney 5 — Behavioral Fingerprinting
Malware örneklerini davranışsal dönem kümelerine ayırır.
K-Means + PCA görselleştirme ile hangi yıl hangi davranışa benzediği analiz edilir.

Kullanım:
    python exp5_fingerprinting.py
"""
import sys
sys.path.insert(0, str(__import__("pathlib").Path(__file__).parents[2]))

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.cm as cm
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import silhouette_score

from config import (
    METADATA_CSV, STATIC_PARQUET,
    FIGURES_DIR, TABLES_DIR, RANDOM_SEED
)

N_CLUSTERS = 6   # davranış dönemi kümesi sayısı (ayarlanabilir)


def find_optimal_k(X_scaled: np.ndarray, k_range=range(3, 10)) -> int:
    """Silhouette skoru ile optimal k seç."""
    scores = {}
    for k in k_range:
        km = KMeans(n_clusters=k, random_state=RANDOM_SEED, n_init=10)
        labels = km.fit_predict(X_scaled)
        scores[k] = silhouette_score(X_scaled, labels)
    best_k = max(scores, key=scores.get)
    print(f"Silhouette skorları: {scores}")
    print(f"Optimal k = {best_k}")
    return best_k


def main():
    meta  = pd.read_csv(METADATA_CSV)[["sha256", "label", "year"]]
    feats = pd.read_parquet(STATIC_PARQUET)
    df    = feats.merge(meta, on="sha256", how="inner")

    # Sadece malware
    malware = df[df.label == 1].copy()
    feat_cols = [c for c in malware.columns if c not in ("sha256", "label", "year")]

    X = malware[feat_cols].fillna(0).values
    scaler   = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Optimal k bul
    best_k = find_optimal_k(X_scaled)

    # K-Means
    kmeans = KMeans(n_clusters=best_k, random_state=RANDOM_SEED, n_init=10)
    malware = malware.copy()
    malware["cluster"] = kmeans.fit_predict(X_scaled)

    # PCA -> 2D görselleştirme
    pca     = PCA(n_components=2, random_state=RANDOM_SEED)
    coords  = pca.fit_transform(X_scaled)
    malware["pca_x"] = coords[:, 0]
    malware["pca_y"] = coords[:, 1]

    # ── Küme-yıl dağılım tablosu ──────────────────────────
    pivot = malware.groupby(["cluster", "year"]).size().unstack(fill_value=0)
    print("\n── Küme × Yıl dağılımı ──")
    print(pivot.to_string())

    TABLES_DIR.mkdir(parents=True, exist_ok=True)
    pivot.to_csv(TABLES_DIR / "exp5_cluster_year.csv")

    # Küme etiketleri (hangi yıllar dominant?)
    cluster_labels = {}
    for c in range(best_k):
        row = pivot.loc[c] if c in pivot.index else pd.Series(dtype=int)
        dominant = row.idxmax() if not row.empty else "?"
        cluster_labels[c] = f"Küme {c}\n({dominant} dominant)"

    # ── PCA scatter ───────────────────────────────────────
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    fig, axes = plt.subplots(1, 2, figsize=(14, 6))

    # Sol: kümeye göre renkli
    colors = cm.tab10(np.linspace(0, 1, best_k))
    for c in range(best_k):
        mask = malware.cluster == c
        axes[0].scatter(malware.loc[mask, "pca_x"], malware.loc[mask, "pca_y"],
                        s=8, alpha=0.5, color=colors[c],
                        label=cluster_labels[c])
    axes[0].set_title("Behavioral Fingerprinting — Kümeler")
    axes[0].set_xlabel("PCA-1"); axes[0].set_ylabel("PCA-2")
    axes[0].legend(fontsize=7, markerscale=2)

    # Sağ: yıla göre renkli
    years      = sorted(malware.year.unique())
    year_colors = cm.viridis(np.linspace(0, 1, len(years)))
    for yr, col in zip(years, year_colors):
        mask = malware.year == yr
        axes[1].scatter(malware.loc[mask, "pca_x"], malware.loc[mask, "pca_y"],
                        s=8, alpha=0.4, color=col, label=str(yr))
    axes[1].set_title("Behavioral Fingerprinting — Yıllar")
    axes[1].set_xlabel("PCA-1"); axes[1].set_ylabel("PCA-2")
    axes[1].legend(fontsize=8, markerscale=2, title="Yıl")

    plt.tight_layout()
    fig.savefig(FIGURES_DIR / "exp5_fingerprinting.png", dpi=150)
    print(f"\nGrafik -> {FIGURES_DIR / 'exp5_fingerprinting.png'}")

    # Küme başına en ayırt edici featurelar
    print("\n── Küme Başına En Önemli Feature'lar ──")
    for c in range(best_k):
        center = kmeans.cluster_centers_[c]
        top5   = pd.Series(center, index=feat_cols).abs().nlargest(5)
        print(f"Küme {c}: {list(top5.index)}")


if __name__ == "__main__":
    main()
