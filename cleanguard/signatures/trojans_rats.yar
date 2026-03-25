/*
    CleanGuard Pro - Trojan & RAT Detection Rules
    Signatures for remote access trojans and trojan downloaders
    Last Updated: 2026-03-24
*/

rule RAT_Reverse_Shell
{
    meta:
        description = "Detects reverse shell patterns using socket connections with command execution"
        severity = "critical"
        author = "CleanGuard Pro"
        date = "2026-03-24"
        category = "rat"

    strings:
        $sock1 = "socket" ascii wide nocase
        $sock2 = "WSASocket" ascii wide nocase
        $sock3 = "WSAStartup" ascii wide nocase
        $sock4 = "SOCK_STREAM" ascii wide nocase
        $sock5 = "AF_INET" ascii wide nocase
        $conn1 = "connect" ascii wide nocase
        $conn2 = "bind" ascii wide nocase
        $conn3 = "listen" ascii wide nocase
        $conn4 = "accept" ascii wide nocase
        $cmd1 = "subprocess" ascii wide nocase
        $cmd2 = "cmd.exe" ascii wide nocase
        $cmd3 = "/bin/sh" ascii wide nocase
        $cmd4 = "/bin/bash" ascii wide nocase
        $cmd5 = "CreateProcess" ascii wide nocase
        $cmd6 = "ShellExecute" ascii wide nocase
        $cmd7 = "popen" ascii wide nocase
        $pipe1 = "CreatePipe" ascii wide nocase
        $pipe2 = "PeekNamedPipe" ascii wide nocase
        $pipe3 = "STARTUPINFO" ascii wide nocase
        $pipe4 = "STARTF_USESTDHANDLES" ascii wide nocase

    condition:
        (1 of ($sock*) and 1 of ($conn*) and 1 of ($cmd*)) or
        (1 of ($sock*) and 1 of ($cmd*) and 1 of ($pipe*))
}

rule RAT_Keylogger
{
    meta:
        description = "Detects keylogging functionality via keyboard hooks and async key state"
        severity = "critical"
        author = "CleanGuard Pro"
        date = "2026-03-24"
        category = "rat"

    strings:
        $hook1 = "GetAsyncKeyState" ascii wide nocase
        $hook2 = "SetWindowsHookEx" ascii wide nocase
        $hook3 = "SetWindowsHookExA" ascii wide nocase
        $hook4 = "SetWindowsHookExW" ascii wide nocase
        $hook5 = "WH_KEYBOARD" ascii wide nocase
        $hook6 = "WH_KEYBOARD_LL" ascii wide nocase
        $hook7 = "GetKeyState" ascii wide nocase
        $hook8 = "GetKeyboardState" ascii wide nocase
        $hook9 = "MapVirtualKey" ascii wide nocase
        $hook10 = "GetForegroundWindow" ascii wide nocase
        $hook11 = "GetWindowText" ascii wide nocase
        $write1 = "WriteFile" ascii wide nocase
        $write2 = "fwrite" ascii wide nocase
        $write3 = "fprintf" ascii wide nocase
        $write4 = "CreateFile" ascii wide nocase
        $write5 = "StreamWriter" ascii wide nocase
        $log1 = "keylog" ascii wide nocase
        $log2 = "keystroke" ascii wide nocase
        $log3 = "keyboard" ascii wide nocase

    condition:
        (2 of ($hook*) and 1 of ($write*)) or
        (1 of ($hook*) and 1 of ($log*))
}

rule RAT_Screen_Capture
{
    meta:
        description = "Detects screen capture and screenshot functionality used by RATs"
        severity = "high"
        author = "CleanGuard Pro"
        date = "2026-03-24"
        category = "rat"

    strings:
        $gdi1 = "BitBlt" ascii wide nocase
        $gdi2 = "GetDC" ascii wide nocase
        $gdi3 = "GetDesktopWindow" ascii wide nocase
        $gdi4 = "CreateCompatibleBitmap" ascii wide nocase
        $gdi5 = "CreateCompatibleDC" ascii wide nocase
        $gdi6 = "SelectObject" ascii wide nocase
        $gdi7 = "StretchBlt" ascii wide nocase
        $gdi8 = "GetSystemMetrics" ascii wide nocase
        $gdi9 = "SM_CXSCREEN" ascii wide nocase
        $gdi10 = "SM_CYSCREEN" ascii wide nocase
        $save1 = "CreateFile" ascii wide nocase
        $save2 = "SaveBitmap" ascii wide nocase
        $save3 = ".bmp" ascii wide nocase
        $save4 = ".png" ascii wide nocase
        $save5 = ".jpg" ascii wide nocase
        $save6 = "GdipSaveImageToFile" ascii wide nocase
        $dotnet1 = "CopyFromScreen" ascii wide nocase
        $dotnet2 = "Screen.PrimaryScreen" ascii wide nocase
        $dotnet3 = "Graphics.FromImage" ascii wide nocase

    condition:
        (3 of ($gdi*) and 1 of ($save*)) or
        2 of ($dotnet*)
}

rule RAT_FileExfiltration
{
    meta:
        description = "Detects file exfiltration patterns - reading, encoding, and transmitting files"
        severity = "critical"
        author = "CleanGuard Pro"
        date = "2026-03-24"
        category = "rat"

    strings:
        $read1 = "ReadFile" ascii wide nocase
        $read2 = "fread" ascii wide nocase
        $read3 = "File.ReadAllBytes" ascii wide nocase
        $read4 = "FileStream" ascii wide nocase
        $read5 = "StreamReader" ascii wide nocase
        $read6 = "open(" ascii wide
        $enc1 = "base64" ascii wide nocase
        $enc2 = "Base64Encode" ascii wide nocase
        $enc3 = "Convert.ToBase64String" ascii wide nocase
        $enc4 = "btoa(" ascii wide nocase
        $enc5 = "b64encode" ascii wide nocase
        $enc6 = "CryptBinaryToString" ascii wide nocase
        $send1 = "HttpSendRequest" ascii wide nocase
        $send2 = "InternetOpen" ascii wide nocase
        $send3 = "WinHttpSendRequest" ascii wide nocase
        $send4 = "WebClient" ascii wide nocase
        $send5 = "UploadData" ascii wide nocase
        $send6 = "UploadFile" ascii wide nocase
        $send7 = "POST" ascii wide
        $send8 = "send(" ascii wide nocase
        $send9 = "requests.post" ascii wide nocase
        $send10 = "urllib" ascii wide nocase

    condition:
        (1 of ($read*) and 1 of ($enc*) and 1 of ($send*)) or
        (1 of ($read*) and 2 of ($send*))
}

rule Trojan_Downloader
{
    meta:
        description = "Detects trojan downloader patterns - downloading and executing payloads"
        severity = "high"
        author = "CleanGuard Pro"
        date = "2026-03-24"
        category = "trojan"

    strings:
        $dl1 = "URLDownloadToFile" ascii wide nocase
        $dl2 = "URLDownloadToFileA" ascii wide nocase
        $dl3 = "URLDownloadToFileW" ascii wide nocase
        $dl4 = "URLDownloadToCacheFile" ascii wide nocase
        $dl5 = "InternetReadFile" ascii wide nocase
        $dl6 = "HttpOpenRequest" ascii wide nocase
        $dl7 = "WinHttpReadData" ascii wide nocase
        $dl8 = "WebClient.DownloadFile" ascii wide nocase
        $dl9 = "wget" ascii wide nocase
        $dl10 = "curl" ascii wide nocase
        $dl11 = "Invoke-WebRequest" ascii wide nocase
        $exec1 = "ShellExecute" ascii wide nocase
        $exec2 = "ShellExecuteEx" ascii wide nocase
        $exec3 = "CreateProcess" ascii wide nocase
        $exec4 = "WinExec" ascii wide nocase
        $exec5 = "system(" ascii wide nocase
        $exec6 = "Process.Start" ascii wide nocase
        $path1 = "\\Temp\\" ascii wide nocase
        $path2 = "%TEMP%" ascii wide nocase
        $path3 = "\\AppData\\Local\\Temp" ascii wide nocase
        $path4 = "\\AppData\\Roaming\\" ascii wide nocase
        $path5 = "GetTempPath" ascii wide nocase
        $path6 = "GetTempFileName" ascii wide nocase

    condition:
        (1 of ($dl*) and 1 of ($exec*)) or
        (1 of ($dl*) and 1 of ($path*) and 1 of ($exec*))
}
