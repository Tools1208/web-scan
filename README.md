# WebScanner
![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

![Banner](https://via.placeholder.com/600x200?text=WebScanner)

---

## 🌐 الوصف (Description)
**WebScanner** هو أداة مسح شاملة لمواقع الويب تدعم فحص الثغرات الشائعة، واكتشاف الملفات المخفية، وتحليل الروابط الداخلية.  
**English**: Comprehensive web scanning tool for detecting common vulnerabilities, hidden files, and analyzing internal links.

---

## ⚙️ الميزات (Features)
| الميزة               | الوصف                                  | Feature                | Description                          |
|----------------------|---------------------------------------|------------------------|--------------------------------------|
| فحص XSS/SQLi         | يكتشف ثغرات حقن الأكواد               | XSS/SQLi Scanning      | Detect code injection vulnerabilities|
| اكتشاف الدلائل       | يبحث عن ملفات مثل `robots.txt`         | Directory Discovery    | Find hidden files/directories        |
| تحليل الروابط        | يجمع الروابط الداخلية تلقائيًا         | Link Crawling          | Automatically collect internal links |
| دعم البروكسي         | للتصفح عبر بروكسي خارجي               | Proxy Support          | Route scans through external proxy  |
| تقارير مفصلة         | يصدر النتائج بتنسيقات JSON/TXT         | Detailed Reports       | Export results in JSON/TXT formats   |

---

## 📦 التثبيت (Installation)

### 1. نسخ المشروع:
```bash
git clone https://github.com/Tools1208/web-scan.git

cd web-scan

chmod +x main.py

** Install ** 

pip install -r requirements.txt

** Use Tool **

python main.py -u https://example.com

python main.py -u https://test.com -t 50 -o scan_results.txt

python main.py -u https://example.com --proxy http://127.0.0.1:8080 -t 50 -o report.json

** Start ** 
python main.py
