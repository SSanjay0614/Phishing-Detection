# 🛡️ Phishing Detection System (Two-Level Protection)

## 📌 Overview
This project implements a **two-level phishing detection framework** that combines **URL-based detection** and **webpage content-based detection** for robust security against phishing attacks.  

Unlike traditional systems that rely only on URL classification, our method first detects suspicious URLs using a **stacking ensemble model**, and then validates the webpage content using a **Large Language Model (LLM)** along with heuristic risk scoring.  

---

## 🚀 Key Features
- **Two-Level Protection**
  1. **URL Phishing Detection** – Uses machine learning on the *PhiUSIIL Phishing URL Dataset*.  
  2. **Webpage Phishing Detection** – Scrapes webpage content and evaluates with a Mistral LLM via Ollama, combined with heuristic scoring.
  
- **Stacking Ensemble Classifier**
  - Base Models: LightGBM, XGBoost, CatBoost  
  - Meta Model: Logistic Regression  
  - Achieved **Accuracy: 99.77%** and **F1-Score: 99.80%**  

- **LLM-Based Webpage Analysis**
  - Mistral LLM (via [Ollama](https://ollama.ai/)) used for phishing classification.  
  - Generates phishing probability score from webpage text.  

- **Heuristic Risk Scoring**
  - Additional risk calculated based on webpage characteristics (pop-ups, ads, suspicious elements, etc.).  
  - Final decision = **50% LLM Score + 50% Heuristic Score**.  

---

## 📂 Dataset
- **[PhiUSIIL Phishing URL Dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset)**  
- A well-known and credible dataset containing labeled phishing and legitimate URLs.  

---

## 🧠 Methodology
1. **URL Detection**
   - Extract features from URLs (length, special characters, domain info, etc.).
   - Train a stacking ensemble:
     ```python
     stacking_clf = Pipeline(steps=[
         ("preprocessor", preprocessor),
         ("model", StackingClassifier(
             estimators=[
                 ("lgbm", LGBMClassifier(n_estimators=200, random_state=42)),
                 ("xgb", XGBClassifier(n_estimators=200, random_state=42, use_label_encoder=False, eval_metric="logloss")),
                 ("cat", CatBoostClassifier(iterations=200, random_seed=42, verbose=0))
             ],
             final_estimator=LogisticRegression(max_iter=2000, class_weight="balanced"),
             passthrough=True,
             cv=5
         ))
     ])
     ```
   - Results:  
     ```
     Accuracy: 0.9977  
     F1-Score: 0.9980  
     ```

2. **Webpage Detection**
   - Scrape webpage HTML content.  
   - Use Mistral LLM via Ollama for phishing prediction.  
   - Extract heuristic signals: number of pop-ups, suspicious links, excessive ads, etc.  
   - Weighted combination:  
     Final Score = 0.5 * LLM Score + 0.5 * Heuristic Risk Score

---

## ⚙️ Tech Stack
- **Machine Learning:** Scikit-learn, LightGBM, XGBoost, CatBoost  
- **Ensemble Learning:** StackingClassifier  
- **LLM Integration:** Mistral via [Ollama](https://ollama.ai/)  
- **Web Scraping:** BeautifulSoup, Requests  
- **Evaluation Metrics:** Accuracy, F1-Score  

---

## 📊 Results
- **URL Phishing Detection:**  
  - Accuracy: **99.77%**  
  - F1-Score: **99.80%**  

- **Webpage Phishing Detection:**  
  - Combines LLM predictions + heuristic risk scoring.  
  - Provides explainable phishing risk.  

---

## 📌 Future Work
- Expand heuristic features (SSL checks, domain reputation, JavaScript activity).  
- Deploy full system as a **FastAPI** or **Flask** API.  
- Integrate browser plugin for real-time phishing protection.  

---

