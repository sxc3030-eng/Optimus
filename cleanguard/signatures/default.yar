/*
    CleanGuard Pro - Default Detection Rules
    Core signatures for general malware detection
    Last Updated: 2026-03-24
*/

rule SuspiciousStrings
{
    meta:
        description = "Detects common suspicious API calls and tool strings used by malware"
        severity = "high"
        author = "CleanGuard Pro"
        date = "2026-03-24"
        category = "general"

    strings:
        $api1 = "CreateRemoteThread" ascii wide nocase
        $api2 = "VirtualAllocEx" ascii wide nocase
        $api3 = "WriteProcessMemory" ascii wide nocase
        $api4 = "NtUnmapViewOfSection" ascii wide nocase
        $api5 = "SetThreadContext" ascii wide nocase
        $api6 = "ResumeThread" ascii wide nocase
        $tool1 = "mimikatz" ascii wide nocase
        $tool2 = "sekurlsa" ascii wide nocase
        $tool3 = "kiwi" ascii wide nocase
        $tool4 = "meterpreter" ascii wide nocase
        $tool5 = "shellcode" ascii wide nocase
        $tool6 = "payload" ascii wide nocase
        $tool7 = "reverse_tcp" ascii wide nocase
        $tool8 = "bind_tcp" ascii wide nocase

    condition:
        any of ($api*) or any of ($tool*)
}

rule ProcessInjection
{
    meta:
        description = "Detects process injection techniques commonly used by malware for evasion"
        severity = "critical"
        author = "CleanGuard Pro"
        date = "2026-03-24"
        category = "injection"

    strings:
        $inject1 = "WriteProcessMemory" ascii wide nocase
        $inject2 = "NtWriteVirtualMemory" ascii wide nocase
        $inject3 = "QueueUserAPC" ascii wide nocase
        $inject4 = "NtQueueApcThread" ascii wide nocase
        $inject5 = "RtlCreateUserThread" ascii wide nocase
        $inject6 = "NtCreateThreadEx" ascii wide nocase
        $inject7 = "SetWindowsHookEx" ascii wide nocase
        $inject8 = "CreateRemoteThread" ascii wide nocase
        $alloc1 = "VirtualAllocEx" ascii wide nocase
        $alloc2 = "NtAllocateVirtualMemory" ascii wide nocase
        $alloc3 = "ZwAllocateVirtualMemory" ascii wide nocase
        $prot1 = "VirtualProtectEx" ascii wide nocase
        $prot2 = "NtProtectVirtualMemory" ascii wide nocase

    condition:
        2 of ($inject*) or (1 of ($alloc*) and 1 of ($inject*)) or (1 of ($prot*) and 1 of ($inject*))
}

rule RansomwareIndicators
{
    meta:
        description = "Detects ransomware behavior patterns including encryption and recovery sabotage"
        severity = "critical"
        author = "CleanGuard Pro"
        date = "2026-03-24"
        category = "ransomware"

    strings:
        $enc1 = "CryptEncrypt" ascii wide nocase
        $enc2 = "CryptGenKey" ascii wide nocase
        $enc3 = "CryptDeriveKey" ascii wide nocase
        $enc4 = "BCryptEncrypt" ascii wide nocase
        $sabotage1 = "vssadmin" ascii wide nocase
        $sabotage2 = "bcdedit" ascii wide nocase
        $sabotage3 = "wbadmin" ascii wide nocase
        $sabotage4 = "shadowcopy" ascii wide nocase
        $sabotage5 = "delete shadows" ascii wide nocase
        $ransom1 = "bitcoin" ascii wide nocase
        $ransom2 = "BTC" ascii wide
        $ransom3 = "wallet" ascii wide nocase
        $ransom4 = "decrypt" ascii wide nocase
        $ransom5 = "YOUR FILES" ascii wide nocase
        $ransom6 = "pay" ascii wide nocase

    condition:
        3 of them
}

rule CredentialHarvesting
{
    meta:
        description = "Detects credential harvesting and dumping tools and techniques"
        severity = "critical"
        author = "CleanGuard Pro"
        date = "2026-03-24"
        category = "credential_theft"

    strings:
        $tool1 = "lazagne" ascii wide nocase
        $tool2 = "procdump" ascii wide nocase
        $tool3 = "mimikatz" ascii wide nocase
        $tool4 = "pypykatz" ascii wide nocase
        $tool5 = "secretsdump" ascii wide nocase
        $target1 = "lsass" ascii wide nocase
        $target2 = "SAM" ascii wide
        $target3 = "NTDS" ascii wide
        $target4 = "SYSTEM" ascii wide
        $target5 = "SECURITY" ascii wide
        $module1 = "sekurlsa" ascii wide nocase
        $module2 = "logonpasswords" ascii wide nocase
        $module3 = "wdigest" ascii wide nocase
        $module4 = "kerberos" ascii wide nocase
        $module5 = "dpapi" ascii wide nocase
        $reg1 = "HKLM\\SAM" ascii wide nocase
        $reg2 = "HKLM\\SECURITY" ascii wide nocase

    condition:
        2 of them
}

rule SuspiciousScriptPatterns
{
    meta:
        description = "Detects obfuscated scripts and encoded payloads in documents and script files"
        severity = "high"
        author = "CleanGuard Pro"
        date = "2026-03-24"
        category = "obfuscation"

    strings:
        $js1 = "fromCharCode" ascii wide nocase
        $js2 = "eval(atob(" ascii wide nocase
        $js3 = "eval(String" ascii wide nocase
        $js4 = "unescape(" ascii wide nocase
        $js5 = "document.write(unescape" ascii wide nocase
        $enc1 = "base64" ascii wide nocase
        $enc2 = "Convert.FromBase64String" ascii wide nocase
        $enc3 = "atob(" ascii wide nocase
        $ps1 = "-EncodedCommand" ascii wide nocase
        $ps2 = "-enc " ascii wide nocase
        $ps3 = "IEX(" ascii wide nocase
        $ps4 = "Invoke-Expression" ascii wide nocase
        $ps5 = "New-Object Net.WebClient" ascii wide nocase
        $ps6 = "DownloadString" ascii wide nocase
        $ps7 = "[System.Convert]::FromBase64String" ascii wide nocase
        $ps8 = "powershell -w hidden" ascii wide nocase
        $ps9 = "bypass" ascii wide nocase
        $vba1 = "Shell(" ascii wide nocase
        $vba2 = "WScript.Shell" ascii wide nocase
        $vba3 = "Scripting.FileSystemObject" ascii wide nocase

    condition:
        3 of ($js*) or 2 of ($ps*) or (1 of ($enc*) and 1 of ($ps*)) or 2 of ($vba*)
}
