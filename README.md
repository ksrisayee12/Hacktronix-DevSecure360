# 🔐 DevSecure360

**DevSecure360** is a **full-stack web application** that performs **vulnerability scanning** for both **source code** and **web applications**.  
It provides developers and security enthusiasts with an interactive dashboard to **monitor**, **analyze**, and **manage** their security scans — all in one place.

---

## 🧭 Table of Contents

1. [Features](#-features)
2. [Tech Stack](#-tech-stack)
3. [Project Structure](#-project-structure)
4. [Installation & Setup](#️-installation--setup)
5. [How It Works](#-how-it-works)
6. [UI Overview](#-ui-preview-structure)
7. [License](#-license)
8. [Ethical Use & Disclaimer](#️-ethical-use--disclaimer)
9. [Contributing](#-contributing)
10. [Author](#-author)

---

## 🚀 Features

- 🧠 **Code Scan** — Analyze local codebases using **Semgrep** to detect security issues.
- 🌐 **External Scan** — Perform **vulnerability testing** on provided URLs.
- 📊 **Dashboard** — Real-time visualization of scan data, severity levels, and risk trends.
- 🧩 **History Tracking** — Access past scans, results, and associated severity metrics.
- 🧱 **Modern UI** — Clean, responsive **React** interface with interactive graphical representation.
- ⚙️ **RESTful Backend** — Powered by **FastAPI**, enabling efficient scan processing and API endpoints.

---

## 🏗️ Tech Stack

### **Frontend**

- ⚛️ React.js
- 🎨 TailwindCSS
- 🔗 Axios (API calls)
- 📊 Chart.js / Recharts (data visualization)

### **Backend**

- 🐍 FastAPI (Python)
- 🔍 Semgrep (static code analysis)
- 🌐 External vulnerability scanner (for URL testing)
- 💾 Local Data Backup (for history storage)

---

## 📂 Project Structure

```plaintext
DevSecure360/
│
├── backend/
|   ├── app/
|   |   ├── database/
|   |       ├── history_db.py
|   |       ├── scan_history.json
│   ├── scanner/
|   |   ├── code_scanner.py
|   |   ├── external_scanner.py
│   ├── utils/
|   |   ├── aggregator.py
│   ├── main.py
│
├── frontend/
│   ├── src/
│   │   ├── assets/
│   │   │   ├── logo.png
│   │   ├── pages/
│   │   │   ├── Dashboard.js
│   │   │   ├── CodeScan.js
│   │   │   ├── ExternalScan.js
│   │   │   ├── History.js
│   │   │   └── About.js
│   │   ├── App.js
│   │   └── index.css
│   └── package.json
│
└── README.md
```

## ⚙️ Installation & Setup

### 1️⃣ Clone the Repository

```
git clone https://github.com/<your-username>/DevSecure360.git
cd DevSecure360
```

### 2️⃣ Backend Setup (FastAPI)

```
cd backend
pip install -r requirements.txt
uvicorn main:app --reload
```

Backend runs at http://127.0.0.1:8000

### 3️⃣ Frontend Setup (React)

```
cd frontend
npm install
npm start
```

Frontend runs at http://localhost:3000

## 🧠 How It Works

### 🔸 Code Scan

- Accepts a local project directory path.
- Scans files using **Semgrep** rules to identify vulnerabilities.
- Displays results with **severity**, **file path**, and **rule details**.
- Stores scan outcomes in the database for future reference.

### 🔸 External Scan

- Accepts a **target URL** (e.g., `https://example.com`).
- Runs a vulnerability analysis using external scanning logic/APIs.
- Reports detected issues, severity breakdowns, and summary scores.

### 🔸 Dashboard

- Provides a real-time view of **scan statistics**, **risk levels**, and **trends**.
- Displays total scans, severity charts, and recent activity history.

## 📜 License

This project is licensed under the **Apache 2.0 License**.  
See the [LICENSE](LICENSE) file for details.

---

## ⚠️ Ethical Use & Disclaimer

> **IMPORTANT NOTICE**  
> DevSecure360 is strictly for **educational**, **research**, and **authorized** security testing only.  
> **Do NOT** use this tool for scanning or penetration testing any system or website without **explicit permission** from the owner.

Unauthorized usage may violate cybersecurity laws.  
Use responsibly, ethically, and within legal boundaries.

---

## 🤝 Contributing

Contributions are welcome!  
To contribute:

1. **Fork** the repository.
2. **Create a feature branch:**

```
   git checkout -b feature-name
```

3. Commit changes and push your branch.

4. Submit a pull request for review.

## 🧩 Author
Project: DevSecure360

Developer: Sri Sayee K

Contact: ksrisayee@gmail.com