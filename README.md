# -WN10-SO-000100
# 📡 Vulnerability Management Lab – WN10-SO-000100

**Title:** The Windows SMB client must be configured to always perform SMB packet signing  
**STIG ID:** WN10-SO-000100  
**Compliance Standards:** DISA STIG, NIST 800-53, HIPAA, PCI DSS  
**Tools Used:** Azure, Windows 10, PowerShell, Tenable.sc / Nessus  
**Lab Type:** Vulnerability Simulation → Detection → Remediation → Verification

---

## 📋 Lab Objective

This lab demonstrates how to detect and remediate a misconfigured **Windows SMB client**, which violates **STIG control WN10-SO-000100**. SMB signing protects against man-in-the-middle (MITM) attacks by ensuring message authenticity and integrity.

### Goals:
- Deploy a Windows 10 VM in Azure  
- Simulate a misconfiguration by disabling SMB packet signing  
- Scan using Tenable’s DISA STIG audit file  
- Remediate via PowerShell  
- Re-scan and confirm compliance  

---

## 📁 Table of Contents

1. [Azure VM Setup](#azure-vm-setup)  
2. [Vulnerability Simulation](#vulnerability-simulation)  
3. [Tenable Scan Configuration](#tenable-scan-configuration)  
4. [Initial Vulnerability Scan](#initial-vulnerability-scan)  
5. [Remediation via PowerShell](#remediation-via-powershell)  
6. [Post-Remediation Verification](#post-remediation-verification)  
7. [Security Rationale](#security-rationale)  
8. [Appendix: PowerShell Commands](#appendix-powershell-commands)

---

## ☁️ Azure VM Setup

### 🔹 Windows 10 VM Provisioning

| Setting              | Value                        |
|----------------------|------------------------------|
| VM Name              | `Win10-STIGLab-SMBSigning`   |
| OS Image             | Windows 10 Pro (Gen 2)       |
| VM Size              | Standard D2s v3              |
| Resource Group       | `vm-lab-smb`                 |
| Region               | Closest to analyst           |

### 🔹 Security Best Practices

> ⚠️ **DO NOT use weak/default credentials** (e.g., `labuser/Cyberlab123!`)  
> ✅ Use strong, complex credentials stored in a password manager or Key Vault.

### 🔹 Network Security Group (NSG)

| Protocol | Port | Direction | Status |
|----------|------|-----------|--------|
| RDP      | 3389 | Inbound   | ✅ Allow |
| WinRM    | 5985 | Inbound   | ✅ Allow (if using remote PowerShell) |
| Others   | Any  | Inbound   | ❌ Deny  |

### 🔹 VM Configuration for Remote Access

#### Disable Windows Firewall (Lab Only)

- Open `wf.msc`  
- Turn off Domain, Private, and Public profiles

#### Allow Remote PowerShell Access

```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
  -Name "LocalAccountTokenFilterPolicy" -Value 1 -Type DWord -Force
```

---

## ⚠️ Vulnerability Simulation

### 🔸 Vulnerability Summary

SMB packet signing ensures that SMB communications are authenticated and tamper-proof. The setting `RequireSecuritySignature` must be set to `1` to **enforce** signing.

### 🔸 Simulate the Vulnerability

```powershell
# Simulate non-compliant SMB configuration (disable packet signing requirement)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
  -Name "RequireSecuritySignature" -Value 0
```

> `0` = SMB signing is not required (non-compliant)  
> `1` = SMB signing is required (compliant)

📸 **Screenshot Placeholder:** `Screenshot_01_SMBSigning_Disabled_PowerShell.png`

---

## 🔍 Tenable Scan Configuration

### 🔸 Scan Template: **Advanced Network Scan**

#### ✅ Basic Settings
- Name: `STIG Scan – SMB Signing Enforcement`
- Target: Azure VM’s public IP

#### ✅ Discovery Settings
- Ping remote host  
- TCP full connect scan  
- NetBIOS / SMB detection

#### ✅ Assessment Settings
- Use local admin credentials (credentialed scan)
- Enable:
  - Remote Registry  
  - Admin Shares  
  - Thorough tests  
  - Server Service enumeration

#### ✅ Compliance Checks
- Upload and assign audit file:  
  `DISA STIG – Microsoft Windows 10 v3r4.audit`

---

## 🧪 Initial Vulnerability Scan

After running the scan in Tenable.sc or Nessus:

| STIG Control        | WN10-SO-000100           |
|---------------------|--------------------------|
| Finding             | SMB packet signing not enforced |
| Status              | ❌ **Fail**               |
| Detected Value      | `RequireSecuritySignature = 0` |
| Required Value      | `RequireSecuritySignature = 1` |

📸 **Screenshot Placeholder:** `Screenshot_02_Tenable_Vuln_Finding_BeforeFix.png`

---

## 🛠️ Remediation via PowerShell

### 🔸 Enforce SMB Packet Signing

```powershell
# Enforce SMB signing to mitigate MITM attacks
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
  -Name "RequireSecuritySignature" -Value 1
```

📸 **Screenshot Placeholder:** `Screenshot_03_PowerShell_Remediation_SMBSigning.png`

> A restart is **recommended** to fully apply SMB-related settings.

---

## 🔁 Post-Remediation Verification

### 🔸 Manual Registry Verification

```powershell
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
  -Name "RequireSecuritySignature"
```

**Expected Output:**
```
RequireSecuritySignature : 1
```

### 🔸 Re-run Tenable Compliance Scan

| STIG Control | WN10-SO-000100 |
|--------------|----------------|
| Status       | ✅ **Pass**     |
| Verified     | SMB Signing Enforced |

📸 **Screenshot Placeholder:** `Screenshot_04_Tenable_AfterRemediation_Pass.png`

---

## 🔐 Security Rationale

### Why This Matters

Without enforced SMB signing:
- SMB traffic can be **intercepted or modified** in transit  
- Systems are vulnerable to **man-in-the-middle (MITM)** attacks  
- Unauthenticated commands may be processed by the SMB server

### Compliance Alignment

| Framework       | Requirement Description                     |
|------------------|---------------------------------------------|
| **DISA STIG**     | WN10-SO-000100                              |
| **NIST 800-53**   | SC-12, SC-23 – Message Integrity            |
| **HIPAA**         | §164.312(e)(1) – Transmission security      |
| **PCI DSS**       | 4.1 – Encrypt transmissions across networks |

---

## 🧼 Post-Lab Cleanup

- ✅ Reboot VM to finalize SMB changes  
- 🧹 Delete lab resources once testing is complete:

```bash
az group delete --name vm-lab-smb --yes --no-wait
```

- 🔐 Remove any saved Tenable credentials or scan records from lab

---

## 📎 Appendix: PowerShell Commands

| Action                    | Command |
|---------------------------|---------|
| Simulate vulnerability    | `Set-ItemProperty -Path HKLM:\SYSTEM\...\LanmanServer\Parameters -Name RequireSecuritySignature -Value 0` |
| Remediate vulnerability   | `Set-ItemProperty -Path HKLM:\SYSTEM\...\LanmanServer\Parameters -Name RequireSecuritySignature -Value 1` |
| Verify registry setting   | `Get-ItemProperty -Path HKLM:\SYSTEM\...\LanmanServer\Parameters -Name RequireSecuritySignature` |
| Enable remote PowerShell  | `Set-ItemProperty -Path HKLM:\...\System -Name LocalAccountTokenFilterPolicy -Value 1` |

---

✅ **Lab Complete**

You've now successfully remediated **WN10-SO-000100**, ensuring SMB packet signing is enforced and compliant with DISA STIG guidance.

Explore the `/labs/` folder for additional vulnerability scenarios.
