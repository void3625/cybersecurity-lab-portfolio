# Cybersecurity Lab Portfolio

資訊管理背景的資安學習作品集，整理我在 TryHackMe 模擬環境中完成的 SOC、SIEM、告警分流與弱點管理實作。

這些報告主要用來記錄我的分析流程、工具操作、初步風險判斷與學習反思。內容皆為 Lab 模擬情境，並非真實企業事件或正式鑑識報告。

## Lab Reports

### 1. [Windows Logging for SOC](reports/windows-logging-for-soc/)

透過 Windows Security Logs 與 Sysmon Logs，練習分析 RDP 登入異常、帳號與權限異動、可疑程式外連、持久化行為及 PowerShell 操作紀錄。

**重點主題：** Windows Event Log、Sysmon、事件關聯、端點調查

---

### 2. [Log Analysis with SIEM](reports/log-analysis-with-siem/)

使用 Splunk 查詢 Windows、Linux 與 Web 伺服器日誌，練習分析 SSH 登入異常、CRON 任務、可疑排程、非標準連線及 Web 登入請求。

**重點主題：** Splunk、跨來源日誌分析、SIEM、事件關聯

---

### 3. [Alert Triage With Splunk](reports/alert-triage-with-splunk/)

透過 Linux 暴力破解、Windows 可疑排程及 Web Shell 情境，練習 SOC 告警分流、時間線比對與初步 True Positive 判斷。

**重點主題：** Alert Triage、Splunk、True Positive、初步事件判斷

---

### 4. [Vulnerability Management](reports/vulnerability-management/)

使用 Greenbone OpenVAS 對模擬 Linux 應用程式伺服器進行弱點掃描，練習解讀掃描結果、風險排序、修復工單與重新掃描驗證流程。

**重點主題：** OpenVAS、弱點管理、風險排序、改善追蹤

---

## Tools and Concepts

* Splunk
* Windows Security Logs
* Sysmon
* Linux auth.log / syslog
* Apache Access Logs
* Greenbone OpenVAS
* MITRE ATT&CK 基礎對應
* Alert Triage
* Incident Investigation
* Vulnerability Management

## Certifications and Learning

* CompTIA Security+ (SY0-701)
* Google Cybersecurity Professional Certificate
* Google Cloud Digital Talent Exploration Program
* ISO/IEC 27001 — In Progress

## About Me

資訊管理學系畢業，具備 Web 開發、資料庫及資訊安全基礎。曾於荷蘭 Amsterdam University of Applied Sciences 參與 Information Security 相關英文授課課程，並持有 IELTS Overall 7.0。

目前希望投入資安事件分析、弱點管理、資安防禦監測與風險改善相關工作。

## Disclaimer

本作品集內容為 TryHackMe 模擬實驗室的學習紀錄，主要用於展示學習過程與分析思路。報告不包含 Flag、考題答案清單或真實組織的敏感資訊。
