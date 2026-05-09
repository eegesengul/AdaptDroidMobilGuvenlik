# AdaptDroid — 4 Kişilik Takım Çalışma Rehberi

## Kimin Ne Yapacağı

| Kişi | Modül | Klasör | Branch |
|------|-------|--------|--------|
| **Kişi 1** | Veri toplama (APK indirme, metadata) | `src/01_collect/` | `feature/data-collection` |
| **Kişi 2** | Statik analiz (feature extraction) | `src/02_static/` | `feature/static-analysis` |
| **Kişi 3** | Dinamik analiz (emülatör pipeline) | `src/03_dynamic/` | `feature/dynamic-analysis` |
| **Kişi 4** | ML modeller + deneyler + SHAP | `src/04_models/` `src/05_experiments/` `src/06_explain/` | `feature/models-experiments` |

---

## İlk Kurulum (Herkese)

```bash
# 1. Repoyu klonla
git clone https://github.com/TAKIMADI/AdaptDroid.git
cd AdaptDroid

# 2. Python ortamı oluştur
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Linux/Mac

# 3. Bağımlılıkları yükle
pip install -r requirements.txt

# 4. config.py içine kendi API key'ini gir (git'e girmiyor)
```

---

## GitHub Repo Oluşturma (Sadece 1 kişi yapar)

```bash
cd C:\AdaptDroid
git init
git add .
git commit -m "ilk commit: proje iskelet yapısı"

# GitHub'da yeni repo aç → AdaptDroid (private)
git remote add origin https://github.com/KULLANICI_ADI/AdaptDroid.git
git branch -M main
git push -u origin main
```

---

## Günlük Çalışma Akışı

### Yeni iş başlarken:
```bash
git checkout main
git pull origin main                    # son değişiklikleri al
git checkout feature/SENIN-BRANCH-ADIN # kendi branch'ine geç
git merge main                          # main'i kendi branch'ine al
```

### Çalışma sırasında (sık commit at):
```bash
git add src/01_collect/download_androzoo.py
git commit -m "androzoo: yıl filtresi eklendi"
git push origin feature/data-collection
```

### İş bitince Pull Request aç:
1. GitHub → "Compare & pull request"
2. Takım arkadaşlarından biri review eder
3. Onay gelince `main`'e merge edilir

---

## Paralel Çalışma — Bağımlılık Sırası

```
Kişi 1 (veri)
    ↓
    metadata.csv hazır olunca →
                               Kişi 2 (statik) çalışmaya başlar
                               Kişi 3 (dinamik) çalışmaya başlar
                                    ↓
                               Her iki parquet hazır olunca →
                                                             Kişi 4 (model) başlar
```

**Kişi 2 ve Kişi 3 tamamen paralel çalışabilir.**

---

## Veri Paylaşımı (APK'lar repo'ya girmez!)

APK'lar `.gitignore`'a ekli, repo'ya girmez.
Büyük dosyaları şu yollardan paylaşın:

**Seçenek A — Google Drive / OneDrive:**
```
data/features/static_features.parquet   → Drive'a yükle, link paylaş
data/features/dynamic_features.parquet  → Drive'a yükle, link paylaş
data/metadata.csv                        → Drive'a yükle, link paylaş
```

**Seçenek B — Ortak bilgisayar / NAS:**
- Bir bilgisayarı ortak veri sunucusu yap
- `config.py` içindeki DATA_DIR'ı o bilgisayarın ağ yoluna çevir

**Seçenek C — Git LFS (önerilen):**
```bash
git lfs install
git lfs track "*.parquet"
git lfs track "data/metadata.csv"
git add .gitattributes
git push
```

---

## Commit Mesajı Kuralları

```
[modül]: kısa açıklama

Örnekler:
  data: androzoo 2025 download scripti tamamlandı
  static: reflection feature'ları eklendi
  dynamic: logcat parse fonksiyonu düzeltildi
  model: adaptive fusion ağırlık hesabı güncellendi
  exp3: drift grafik kaydediliyor artık
  fix: metadata.csv yıl parse hatası giderildi
```

---

## Çakışma Önleme Kuralları

1. **Her kişi sadece kendi modül klasörüne** yazar
2. `config.py` değişikliği gerekirse önce gruba sor
3. `data/` altına hiçbir şey commit etme
4. Branch'ini her sabah `main`'den güncelle

---

## Sprint Planı (8 Hafta)

| Hafta | Kişi 1 | Kişi 2 | Kişi 3 | Kişi 4 |
|-------|--------|--------|--------|--------|
| 1 | Ortam kur, API key al | Ortam kur, Androguard test | Emülatör kur, ADB test | Ortam kur, LightGBM test |
| 2 | AndroZoo indirme | - | - | - |
| 3 | F-Droid + metadata.csv | Statik extraction başla | Dinamik pipeline yaz | - |
| 4 | İndirme tamamla | Statik extraction devam | Dinamik analiz çalıştır | E1+E2 deneyleri |
| 5 | VirusTotal label doğrula | static_features.parquet | dynamic_features.parquet | E3 drift analizi |
| 6 | Destek | Feature kalite kontrol | Destek | E4 rolling retrain |
| 7 | Destek | SHAP destek | Destek | E5 fingerprinting + SHAP |
| 8 | Sonuç tabloları | Sonuç tabloları | Sonuç tabloları | Final rapor |
