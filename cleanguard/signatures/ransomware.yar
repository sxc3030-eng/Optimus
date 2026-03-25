/*
    CleanGuard Pro - Ransomware Detection Rules
    Specialized signatures for ransomware families and behaviors
    Last Updated: 2026-03-24
*/

rule Ransomware_FileExtension
{
    meta:
        description = "Detects mass file renaming with known ransomware extensions"
        severity = "critical"
        author = "CleanGuard Pro"
        date = "2026-03-24"
        category = "ransomware"

    strings:
        $ext1 = ".locked" ascii wide nocase
        $ext2 = ".crypt" ascii wide nocase
        $ext3 = ".encrypted" ascii wide nocase
        $ext4 = ".wncry" ascii wide nocase
        $ext5 = ".cerber" ascii wide nocase
        $ext6 = ".locky" ascii wide nocase
        $ext7 = ".zepto" ascii wide nocase
        $ext8 = ".odin" ascii wide nocase
        $ext9 = ".aesir" ascii wide nocase
        $ext10 = ".osiris" ascii wide nocase
        $ext11 = ".ryuk" ascii wide nocase
        $ext12 = ".REvil" ascii wide
        $ext13 = ".sodinokibi" ascii wide nocase
        $ext14 = ".lockbit" ascii wide nocase
        $ext15 = ".conti" ascii wide nocase
        $ext16 = ".hive" ascii wide nocase
        $ext17 = ".blackcat" ascii wide nocase
        $ext18 = ".phobos" ascii wide nocase
        $ext19 = ".dharma" ascii wide nocase
        $ext20 = ".STOP" ascii wide
        $ext21 = ".djvu" ascii wide nocase
        $rename1 = "MoveFileEx" ascii wide nocase
        $rename2 = "MoveFileW" ascii wide nocase
        $rename3 = "rename" ascii wide nocase
        $enum1 = "FindFirstFile" ascii wide nocase
        $enum2 = "FindNextFile" ascii wide nocase

    condition:
        3 of ($ext*) and (1 of ($rename*) or 1 of ($enum*))
}

rule Ransomware_NotePattern
{
    meta:
        description = "Detects ransom note text patterns across multiple ransomware families"
        severity = "critical"
        author = "CleanGuard Pro"
        date = "2026-03-24"
        category = "ransomware"

    strings:
        $note1 = "YOUR FILES HAVE BEEN ENCRYPTED" ascii wide nocase
        $note2 = "your personal files are encrypted" ascii wide nocase
        $note3 = "All your files have been encrypted" ascii wide nocase
        $note4 = "your documents, photos, databases" ascii wide nocase
        $note5 = "pay bitcoin" ascii wide nocase
        $note6 = "pay in bitcoin" ascii wide nocase
        $note7 = "bitcoin wallet" ascii wide nocase
        $note8 = "decrypt files" ascii wide nocase
        $note9 = "decrypt your files" ascii wide nocase
        $note10 = "send bitcoin" ascii wide nocase
        $note11 = "unique decryption key" ascii wide nocase
        $note12 = "decryption tool" ascii wide nocase
        $note13 = "recover your files" ascii wide nocase
        $note14 = "README_TO_DECRYPT" ascii wide nocase
        $note15 = "HOW_TO_DECRYPT" ascii wide nocase
        $note16 = "RESTORE_FILES" ascii wide nocase
        $note17 = "DECRYPT_INSTRUCTION" ascii wide nocase
        $note18 = "ransom" ascii wide nocase
        $note19 = "We have encrypted" ascii wide nocase
        $note20 = "payment is required" ascii wide nocase
        $btc1 = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii wide
        $tor1 = ".onion" ascii wide nocase

    condition:
        2 of ($note*) or (1 of ($note*) and ($btc1 or $tor1))
}

rule Ransomware_ShadowDelete
{
    meta:
        description = "Detects ransomware recovery sabotage - shadow copy and backup deletion"
        severity = "critical"
        author = "CleanGuard Pro"
        date = "2026-03-24"
        category = "ransomware"

    strings:
        $shadow1 = "vssadmin delete shadows" ascii wide nocase
        $shadow2 = "vssadmin.exe delete shadows" ascii wide nocase
        $shadow3 = "vssadmin Delete Shadows /All /Quiet" ascii wide nocase
        $wmic1 = "wmic shadowcopy delete" ascii wide nocase
        $wmic2 = "WMIC.exe shadowcopy delete" ascii wide nocase
        $wmic3 = "Win32_ShadowCopy" ascii wide nocase
        $bcdedit1 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" ascii wide nocase
        $bcdedit2 = "bcdedit /set {default} recoveryenabled no" ascii wide nocase
        $bcdedit3 = "bcdedit.exe /set" ascii wide nocase
        $wbadmin1 = "wbadmin delete catalog" ascii wide nocase
        $wbadmin2 = "wbadmin DELETE SYSTEMSTATEBACKUP" ascii wide nocase
        $ps_shadow = "Get-WmiObject Win32_ShadowCopy | ForEach-Object" ascii wide nocase
        $disable1 = "net stop VSS" ascii wide nocase
        $disable2 = "net stop \"Volume Shadow Copy\"" ascii wide nocase
        $disable3 = "sc config VSS start= disabled" ascii wide nocase
        $recycle = "cipher /w:" ascii wide nocase

    condition:
        2 of them
}

rule Ransomware_KeyGeneration
{
    meta:
        description = "Detects ransomware encryption key generation and file encryption patterns"
        severity = "critical"
        author = "CleanGuard Pro"
        date = "2026-03-24"
        category = "ransomware"

    strings:
        $keygen1 = "CryptGenRandom" ascii wide nocase
        $keygen2 = "BCryptGenRandom" ascii wide nocase
        $keygen3 = "RtlGenRandom" ascii wide nocase
        $keygen4 = "CryptGenKey" ascii wide nocase
        $aes1 = "AES" ascii wide
        $aes2 = "CALG_AES_256" ascii wide nocase
        $aes3 = "aes-256-cbc" ascii wide nocase
        $aes4 = "AesManaged" ascii wide nocase
        $aes5 = "RijndaelManaged" ascii wide nocase
        $rsa1 = "RSA" ascii wide
        $rsa2 = "CALG_RSA_KEYX" ascii wide nocase
        $rsa3 = "RSACryptoServiceProvider" ascii wide nocase
        $rsa4 = "CryptImportKey" ascii wide nocase
        $rsa5 = "RSA_PKCS1_OAEP_PADDING" ascii wide nocase
        $fileop1 = "ReadFile" ascii wide nocase
        $fileop2 = "WriteFile" ascii wide nocase
        $fileop3 = "CreateFileW" ascii wide nocase
        $fileop4 = "SetFilePointer" ascii wide nocase
        $encrypt1 = "CryptEncrypt" ascii wide nocase
        $encrypt2 = "BCryptEncrypt" ascii wide nocase
        $encrypt3 = "CryptDestroyKey" ascii wide nocase

    condition:
        (1 of ($keygen*)) and (1 of ($aes*) or 1 of ($rsa*)) and (1 of ($fileop*) or 1 of ($encrypt*))
}
