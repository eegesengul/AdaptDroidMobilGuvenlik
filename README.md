# AdaptDroidMobilGuvenlik

Android zararlı yazılım analizi, statik/dinamik özellik çıkarımı ve modelleme için hazırlanmış bir Python projesi.

## İçerik
- `src/` altında analiz ve yardımcı modüller
- `config.py` ile proje yolları ve sabitler
- `build_dataset.py` ile özellik setlerini birleştirme
- `requirements.txt` ile bağımlılıklar
- `frida_project/` altında Frida hook kodları

## Kurulum
```cmd
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Kullanım
Projede hangi dosyanın ne yaptığını görmek için önce şu dosyalara bak:
- `config.py`
- `build_dataset.py`
- `src/`

Veri klasörleri ve üretim çıktıları çok büyük olabileceği için repoya yalnızca gerekli kaynak dosyaları ekle, üretilen dosyaları ise dışarıda bırak.

## GitHub'a temiz yükleme
Önerilen akış:
```cmd
git status
git add .
git commit -m "Clean project for GitHub"
git branch -M main
git remote add origin https://github.com/KULLANICI_ADIN/REPO_ADI.git
git push -u origin main
```

Eğer `origin` zaten ekliyse `git remote add` satırını atlayabilirsin.

## Notlar
- `.venv/`, `.idea/`, `__pycache__/` gibi klasörler repoya eklenmez.
- Büyük veri dosyaları için gerekirse Git LFS kullan.
