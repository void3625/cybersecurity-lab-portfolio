# TryHackMe Lab Report： Windows Logging for SOC
Windows 事件日誌分析與 SOC 調查練習
## 1. 執行摘要 
本報告整理 TryHackMe「Windows Logging for SOC」Lab 的練習過程，目標是透過 Windows Security Logs 與 Sysmon Logs，學習如何觀察可疑登入、帳號異動、權限變更、惡意程式執行與 PowerShell 操作紀錄。

在 Lab 情境中，受害主機 THM-PC 出現疑似 RDP 暴力破解、可疑帳號建立、敏感權限群組異動、惡意程式外連與 PowerShell 操作等跡象。本次練習重點不在於真實企業事件處理，而是透過模擬情境熟悉 SOC 初步調查流程、Windows Event ID 判讀、Sysmon Log 分析與基礎改善建議整理。

---

## 2. 威脅分析與日誌鑑識過程 

### 📌 階段一： RDP 暴力破解偵測 (Task 3)
* **分析日誌：** `Practice-Security.evtx`
* **關鍵事件 ID：** Event ID `4625` (登入失敗), Event ID `4624` (登入成功), Logon Type `10`：RemoteInteractive，常見於 RDP 登入
* **鑑識發現：** 系統日誌在短時間內產生密集的 **Event ID 4625**，且 `Logon Type` 為 `10`（遠端桌面 RDP），顯示疑似遭受自動化暴力破解。隨後，日誌記錄到一筆來自相同惡意來源的 **Event ID 4624** 成功登入事件。兩者存在約 10 分鐘的時間差，符合攻擊者自動化猜中密碼後，改以人工登入的時間延遲。
* **初步風險判斷**: 若在真實企業環境中觀察到短時間大量 RDP 登入失敗，後續又出現成功登入，應進一步檢查來源 IP、使用者帳號、登入時間與該帳號後續行為，確認是否為合法登入或可疑入侵。

> 📸 **實證截圖 1 - RDP 登入分析：**
> 
![螢幕擷取畫面 2026-06-14 145753]

---

### 📌 階段二：帳號建立與權限提升 (Task 4)
* **分析日誌：** `Practice-Security.evtx`
* **關鍵事件 ID：** Event ID `4720` (建立使用者), Event ID `4732` (加入安全群組)
* **鑑識發現：** 在成功登入後，日誌中觀察到一個名為 svc_sysrestore 的本地帳號被建立。在 **Event ID 4732**（加入群組）的預設 General 畫面中，`Member Account Name` 欄位因為離線環境無法即時解析 SID 而顯示為 `-`。
* **跨事件關聯：** 我透過 **Subject Logon ID (0x183C36D)** 進行跨事件關聯，確認此操作與前一刻建立帳號的惡意主體為同一人。該可疑帳號隨即被加入 `Backup Operators` 敏感特權群組，此群組能繞過系統 ACL 限制，通常被攻擊者用來準備竊取資料。

> 📸 **實證截圖 2 - 帳號提權分析：**
> 
![螢幕擷取畫面 2026-06-14 151433]

---

### 📌 階段三：惡意軟體落地與 C2 外連 (Task 5 & 6)
* **分析日誌：** `Practice-Sysmon.evtx`
* **關鍵事件 ID：** Event ID `1` (進程建立), Event ID `15` (檔案流建立), Event ID `3` (網路連線), Event ID `11` (檔案建立)
* **鑑識發現：** 1. **下載網址逆向：** 透過 Sysmon Event ID 3 鎖定了惡意程式 `ckjg.exe` 連線至外部 C2 IP `193.46.217.4:7777` 的紀錄，但因事件欄位限制未顯示完整 URL。我利用 Windows NTFS 的 Alternate Data Streams (ADS) 機制，審查 **Sysmon Event ID 15 (`:Zone.Identifier`)**，成功在 `HostUrl` 中還原出精確的惡意下載鏈結：`http://gettsveriff.com/bgj3/ckjg.exe`。
  2. **持久化機制：** 透過 **Sysmon Event ID 11**，發現惡意程式 `ckjg.exe` 執行後，在系統的 Startup（啟動）目錄下釋放了一個副本，企圖實施開機自動執行的持久化控制。
* **初步風險判斷**： 若可疑執行檔同時出現外部連線、Startup 目錄落地與不明來源下載紀錄，可能代表該主機存在惡意程式執行與持久化風險。在真實環境中，應進一步蒐集檔案 Hash、執行路徑、來源 URL、C2 IP，並確認是否有其他端點出現相同 IOC。
> 📸 **實證截圖 3 - Zone.Identifier 來源網址提取：**

![螢幕擷取畫面 2026-06-14 154910]

---

### 📌 階段四：PowerShell 內網活動獵捕 (Task 7)
* **分析路徑：** `C:\Users\<User>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`
* **鑑識發現：** 在追查 PowerShell 歷史紀錄時，提示給的自動化搜尋指令因環境權限限制而拋出紅字錯誤。我改用最基本的 `cd C:\Users\` 和 `Get-ChildItem -Recurse` 去手動翻目錄，最後順利在 `thm.bob` 的歷史檔案裡找到關鍵證據（Flag）：
  `echo "THM{it_was_me!}" > flag.txt`

> 📸 **實證截圖 4 - PowerShell 手工鑑識成果：**

![螢幕擷取畫面 2026-06-14 161804]

---
## 3.MITRE ATT&CK 對應練習

###  攻擊行為與技術對應分析

>  **備註：** 以下分析僅為依據 Lab 情境進行的初步練習，實際企業事件仍需要搭配更多端點、網路、EDR 與威脅情資資料進行綜合確認。

| 觀察行為 (Observed Behavior) | 可能對應的攻擊技術 (Technique) | 參考說明 (Notes) |
| :--- | :--- | :--- |
| 多次 RDP 登入失敗後成功登入 | **Brute Force / Remote Services** | 疑似遭遇暴力破解攻擊，隨後進行遠端服務橫向移動。 |
| 建立 `svc_sysrestore` 本地帳號 | **Create Account** | 攻擊者建立新帳號以維持權限（Persistence）。 |
| 將帳號加入 `Backup Operators` 群組 | **Account Manipulation** | 權限提升或帳號權限竄改，藉此取得高權限存取能力。 |
| 可疑檔案出現在 Startup 目錄 | **Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder** | 經典的持久化潛伏（Persistence）手法，確保重開機後能自動執行。 |
| `ckjg.exe` 對外連線 | **Command and Control (C2)** | 惡意程式試圖與外部控制伺服器建立連線。 |
| PowerShell 操作紀錄 | **Command and Scripting Interpreter: PowerShell** | 執行惡意腳本或進行防禦繞過、環境偵查。 |

## 4. 初步改善建議方向
###### 以下改善方向為依據 Lab 情境整理的初步建議，實際企業環境仍需依照資產重要性、現有工具、網路架構與內部流程進行調整。
### 1. RDP 與登入安全 (Identity & Access Control)
* **邊界防護：** 嚴禁 RDP (`3389/TCP`) 直接對網際網路開放。應強制改由 **VPN**、**跳板機 (Bastion Host)** 或 **零信任架構 (Zero Trust Network Access, ZTNA)** 進行遠端存取。
* **多因素驗證：** 全面啟用 **MFA (Multi-Factor Authentication)**，以降低憑證外洩（Credential Stuffing）或密碼遭猜測後被直接登入的風險。
* **帳號鎖定政策：** 設定嚴格的密碼複雜度與「帳號鎖定政策」（例如：連續失敗 5 次鎖定 30 分鐘），以有效阻絕暴力破解（Brute Force）攻擊。
* **SIEM 監控告警：** 針對端點或網域控制站（DC）在短時間內產生大量 `Event ID 4625`（登入失敗）隨後緊接 `Event ID 4624`（登入成功）的異常行為，建立高優先級的 SIEM 告警規則。

---

### 2. 帳號與權限管理 (Privilege Management)
* **定期稽核：** 建立自動化機制，定期稽核本機帳號（Local Accounts）與高權限群組成員的變動。
* **敏感群組監控：** 針對以下敏感群組進行重點監控，任何人員異動皆須落實變更管理流程：
    * `Administrators`
    * `Backup Operators`
    * `Remote Desktop Users`
* **關鍵事件告警：** 針對 Windows 安全事件日誌中的關鍵 ID 建立即時告警：
    * `Event ID 4720`：建立新使用者帳號。
    * `Event ID 4732`：將成員新增至具備安全性功能的本機群組。
* **最小權限原則：** 調查過程中若發現無法確認用途的未知帳號（如本次發現之 `svc_sysrestore`），應**立即停用**而非刪除，以利後續鑑識調查。

---

### 3. 端點防護與惡意程式處理 (Endpoint Security & IR)
* **緊急網路隔離：** 確診受害主機後，應第一時間利用 EDR 或網路交換器進行**主機隔離（Isolation）**，切斷其網路連線，避免惡意程式持續外連（C2）或在內部進行橫向移動（Lateral Movement）。
* **IOC 威脅情資蒐集：** 迅速提取本次事件之關鍵威脅指標（Indicators of Compromise），包括：
    * 惡意檔案雜湊值（File Hash, MD5/SHA256）
    * 異常檔案路徑（如：`Startup` 目錄、`C:\Windows\Temp\`）
    * 外部中繼站（C2 IP / Domain，例如 `ckjg.exe` 的外連目標）
* **持久化機制檢查：** 定期排查並清除 Windows `Startup` 目錄、`Registry Run Keys`、排程工作（Scheduled Tasks）等常見的持久化（Persistence）潛伏點。
* **全面深度掃描：** 導入 **EDR (Endpoint Detection and Response)** 進行記憶體與磁鑑識，或使用防毒工具進行全機完整掃描。

---


## 5. 學習心得與反思 

做完這個 Room 最大的感想是，雖然現在有各種高階的資安工具（像 EDR 或自動化腳本）可以幫忙處理大部分的事、節省很多調查時間，但原始日誌和作業系統的「基本功」還是必須要會。

像在 Task 5 找惡意網址時，網路連線日誌因為限制就是不會顯示 URL，這時候如果只依賴現成工具，調查就卡住了。必須要懂 Windows 底層的 `:Zone.Identifier`（Event ID 15），才能真的把惡意網域撈出來。

另外在 Task 7 找 PowerShell 歷史紀錄時，提示給的自動化搜尋指令直接在虛擬機噴紅字報錯。在實務上工具壞掉或環境有問題是很常發生的，如果沒弄懂底層路徑，工具失效就不知道該怎麼辦。那時候我改用最基本的 `cd` 和 `Get-ChildItem` 去手動翻目錄，最後才順利在 `thm.bob` 的檔案裡找到關鍵證據。

這讓我體會到，工具只是輔助，在工具查不到或出錯的時候，看得懂 Raw Log 並且知道怎麼手動去排錯，才是能真正解決問題的關鍵。
