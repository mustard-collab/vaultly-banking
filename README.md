# 🌐 VAULTLY — Digital Banking Suite

My official neo-banking web application — built to provide a secure, real-time digital banking experience with zero-trust security architecture, automated PDF statement generation, and dynamic virtual card switching.

🔗 **Live App:** [https://vaultly-banking.vercel.app](https://vaultly-banking.vercel.app)  
🛡️ **Admin Command Center:** [https://vaultly-banking.vercel.app/admin](https://vaultly-banking.vercel.app/admin)

---

### 🎯 About This Project

VAULTLY is an enterprise-grade digital banking suite designed to simulate real-world financial operations. It features email-based OTP multi-factor authentication (2FA), instant inter-bank (1LINK/Raast) transfers, utility bill settlements, and live doubly linked-list passbook synchronization across multiple client sessions.

---

### ✨ Features

* **Multi-Factor Authentication & 2FA:** Secure account registration and login backed by real-time email OTP verification.
* **Dynamic Virtual Cards:** Real-time network switching between **VISA Infinite** and **Mastercard World Elite** with custom spending limits and freeze toggles.
* **Smart Inter-Bank Transfers:** Instant fund transfers supporting same-bank free settlement and 1LINK/Raast cross-bank tax integration (PKR 30 fee logic).
* **Encrypted PDF E-Statements:** Calendar date-range filtered encrypted statement generator dispatched straight to users' email inboxes.
* **Admin AML & Security Radar:** Real-time anti-fraud transaction tracking, circular laundering detection graphs, account freezing, and Master CSV/JSON audit exports.

---

### 🛠️ Tech Stack

| Layer | Technology |
| :--- | :--- |
| **Backend Core** | Python, Flask, Gunicorn |
| **Data Structures** | Custom Hash Tables, Doubly Linked Lists, Sliding Window Rate Limiters, Min-Heaps, Directed Graphs |
| **Frontend UI** | HTML5, Tailwind CSS, JavaScript (ES6+), HTML2Canvas |
| **Security & Cryptography** | Salted Password Hashing, ReportLab (Encrypted PDFs), SMTPLib (2FA Dispatch) |
| **Deployment** | Vercel Serverless / Persistent JSON Engine |

---

### 📄 License

All Rights Reserved. This code is publicly viewable for portfolio and demonstration purposes only.

---

### 👤 Author

**Muhammad Mustafa Khan**  
*AI-Empowered Full-Stack Developer & Computer Networks & Security Student @ SSUET*

* **GitHub:** [@mustard-collab](https://github.com/mustard-collab)
* **LinkedIn:** [muhammad-mustafa11](https://www.linkedin.com/in/muhammad-mustafa11/)
* **Portfolio:** [mustard-collab.github.io/portfolio](https://mustard-collab.github.io/portfolio)
