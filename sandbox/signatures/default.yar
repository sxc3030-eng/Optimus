/*
 * NetGuardPro Sandbox — Default YARA Rules
 * ==========================================
 * Basic rules for detecting common malicious patterns.
 * Add custom .yar files to this directory for extended detection.
 */

rule SuspiciousStrings {
    meta:
        description = "Common suspicious API calls and tool names"
        severity = "high"
        author = "NetGuardPro Sandbox"
    strings:
        $s1 = "CreateRemoteThread" ascii
        $s2 = "VirtualAllocEx" ascii
        $s3 = "mimikatz" ascii nocase
        $s4 = "Invoke-Expression" ascii nocase
        $s5 = "powershell -enc" ascii nocase
    condition:
        any of them
}

rule ProcessInjection {
    meta:
        description = "Process injection technique indicators"
        severity = "critical"
        author = "NetGuardPro Sandbox"
    strings:
        $a1 = "WriteProcessMemory" ascii
        $a2 = "NtWriteVirtualMemory" ascii
        $a3 = "RtlCreateUserThread" ascii
        $a4 = "QueueUserAPC" ascii
        $a5 = "SetWindowsHookEx" ascii
    condition:
        2 of them
}

rule RansomwareIndicators {
    meta:
        description = "Possible ransomware behavior indicators"
        severity = "critical"
        author = "NetGuardPro Sandbox"
    strings:
        $r1 = "CryptEncrypt" ascii
        $r2 = "CryptGenKey" ascii
        $r3 = "vssadmin" ascii nocase
        $r4 = "bcdedit" ascii nocase
        $r5 = "wbadmin" ascii nocase
        $r6 = "Your files have been encrypted" ascii nocase
        $r7 = "bitcoin" ascii nocase
        $r8 = ".onion" ascii
    condition:
        3 of them
}

rule CredentialHarvesting {
    meta:
        description = "Credential harvesting tool indicators"
        severity = "high"
        author = "NetGuardPro Sandbox"
    strings:
        $c1 = "lazagne" ascii nocase
        $c2 = "procdump" ascii nocase
        $c3 = "lsass" ascii nocase
        $c4 = "SAM database" ascii nocase
        $c5 = "sekurlsa" ascii nocase
    condition:
        2 of them
}

rule SuspiciousScriptPatterns {
    meta:
        description = "Obfuscated or suspicious script patterns"
        severity = "medium"
        author = "NetGuardPro Sandbox"
    strings:
        $p1 = "fromCharCode" ascii
        $p2 = "String.fromCharCode" ascii
        $p3 = "eval(atob(" ascii
        $p4 = "exec(base64" ascii nocase
        $p5 = "powershell -nop -w hidden" ascii nocase
        $p6 = "IEX(New-Object" ascii nocase
    condition:
        any of them
}
