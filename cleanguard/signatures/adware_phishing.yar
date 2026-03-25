/*
    CleanGuard Pro - Adware & Phishing Detection Rules
    Signatures for phishing pages, credential harvesting forms, and adware overlays
    Last Updated: 2026-03-24
*/

rule Phishing_Credential_Form
{
    meta:
        description = "Detects phishing credential harvesting forms with password inputs and suspicious targets"
        severity = "high"
        author = "CleanGuard Pro"
        date = "2026-03-24"
        category = "phishing"

    strings:
        $input1 = "type=\"password\"" ascii wide nocase
        $input2 = "type='password'" ascii wide nocase
        $input3 = "input type=password" ascii wide nocase
        $input4 = "name=\"pass\"" ascii wide nocase
        $input5 = "name=\"password\"" ascii wide nocase
        $input6 = "name=\"passwd\"" ascii wide nocase
        $form1 = "action=\"http" ascii wide nocase
        $form2 = "action='http" ascii wide nocase
        $form3 = "method=\"post\"" ascii wide nocase
        $form4 = "method='post'" ascii wide nocase
        $form5 = "action=" ascii wide nocase
        $sus1 = "verify" ascii wide nocase
        $sus2 = "confirm" ascii wide nocase
        $sus3 = "secure" ascii wide nocase
        $sus4 = "update" ascii wide nocase
        $sus5 = "account" ascii wide nocase
        $sus6 = "login" ascii wide nocase
        $sus7 = "signin" ascii wide nocase
        $sus8 = "authenticate" ascii wide nocase
        $exfil1 = "XMLHttpRequest" ascii wide nocase
        $exfil2 = "fetch(" ascii wide nocase
        $exfil3 = "FormData" ascii wide nocase
        $exfil4 = "navigator.sendBeacon" ascii wide nocase

    condition:
        (1 of ($input*) and 1 of ($form*) and 2 of ($sus*)) or
        (1 of ($input*) and 1 of ($exfil*) and 1 of ($sus*))
}

rule Phishing_BankClone
{
    meta:
        description = "Detects cloned banking login pages used for credential phishing"
        severity = "critical"
        author = "CleanGuard Pro"
        date = "2026-03-24"
        category = "phishing"

    strings:
        $bank1 = "Bank of America" ascii wide nocase
        $bank2 = "Chase" ascii wide nocase
        $bank3 = "Wells Fargo" ascii wide nocase
        $bank4 = "Citibank" ascii wide nocase
        $bank5 = "HSBC" ascii wide nocase
        $bank6 = "Barclays" ascii wide nocase
        $bank7 = "Deutsche Bank" ascii wide nocase
        $bank8 = "PayPal" ascii wide nocase
        $bank9 = "Credit Suisse" ascii wide nocase
        $bank10 = "Santander" ascii wide nocase
        $bank11 = "ING" ascii wide nocase
        $bank12 = "BNP Paribas" ascii wide nocase
        $login1 = "type=\"password\"" ascii wide nocase
        $login2 = "type='password'" ascii wide nocase
        $login3 = "login" ascii wide nocase
        $login4 = "sign in" ascii wide nocase
        $login5 = "username" ascii wide nocase
        $login6 = "user id" ascii wide nocase
        $login7 = "online banking" ascii wide nocase
        $ssl1 = "ssl" ascii wide nocase
        $ssl2 = "secure" ascii wide nocase
        $ssl3 = "encrypted" ascii wide nocase
        $ssl4 = "certificate" ascii wide nocase
        $ssl5 = "https://" ascii wide nocase
        $padlock = "padlock" ascii wide nocase

    condition:
        (1 of ($bank*) and 1 of ($login*) and 1 of ($ssl*)) or
        (2 of ($bank*) and 2 of ($login*))
}

rule Adware_Overlay
{
    meta:
        description = "Detects adware overlay techniques - always-on-top windows and click interception"
        severity = "medium"
        author = "CleanGuard Pro"
        date = "2026-03-24"
        category = "adware"

    strings:
        $overlay1 = "HWND_TOPMOST" ascii wide nocase
        $overlay2 = "SetWindowPos" ascii wide nocase
        $overlay3 = "SWP_NOMOVE" ascii wide nocase
        $overlay4 = "WS_EX_TOPMOST" ascii wide nocase
        $overlay5 = "WS_EX_LAYERED" ascii wide nocase
        $overlay6 = "SetLayeredWindowAttributes" ascii wide nocase
        $overlay7 = "WS_EX_TRANSPARENT" ascii wide nocase
        $overlay8 = "always-on-top" ascii wide nocase
        $click1 = "SetCapture" ascii wide nocase
        $click2 = "mouse_event" ascii wide nocase
        $click3 = "SendInput" ascii wide nocase
        $click4 = "BlockInput" ascii wide nocase
        $click5 = "GetCursorPos" ascii wide nocase
        $click6 = "SetCursorPos" ascii wide nocase
        $css1 = "z-index: 99999" ascii wide nocase
        $css2 = "z-index:99999" ascii wide nocase
        $css3 = "position: fixed" ascii wide nocase
        $css4 = "position:fixed" ascii wide nocase
        $css5 = "pointer-events" ascii wide nocase
        $css6 = "opacity: 0" ascii wide nocase

    condition:
        (2 of ($overlay*) and 1 of ($click*)) or
        (1 of ($overlay*) and 2 of ($click*)) or
        (3 of ($css*))
}

rule Adware_PopupGenerator
{
    meta:
        description = "Detects adware popup and push notification abuse patterns"
        severity = "medium"
        author = "CleanGuard Pro"
        date = "2026-03-24"
        category = "adware"

    strings:
        $notif1 = "Notification.requestPermission" ascii wide nocase
        $notif2 = "PushManager" ascii wide nocase
        $notif3 = "pushSubscription" ascii wide nocase
        $notif4 = "serviceWorker.register" ascii wide nocase
        $notif5 = "showNotification" ascii wide nocase
        $notif6 = "push-subscription" ascii wide nocase
        $popup1 = "window.open(" ascii wide nocase
        $popup2 = "window.open (" ascii wide nocase
        $popup3 = "popunder" ascii wide nocase
        $popup4 = "pop_under" ascii wide nocase
        $popup5 = "clickunder" ascii wide nocase
        $popup6 = "tabunder" ascii wide nocase
        $chain1 = "setTimeout" ascii wide nocase
        $chain2 = "setInterval" ascii wide nocase
        $chain3 = "onclick" ascii wide nocase
        $chain4 = "onbeforeunload" ascii wide nocase
        $chain5 = "onunload" ascii wide nocase
        $chain6 = "addEventListener" ascii wide nocase
        $evade1 = "window.focus" ascii wide nocase
        $evade2 = "window.blur" ascii wide nocase
        $evade3 = "document.hasFocus" ascii wide nocase
        $evade4 = "visibilitychange" ascii wide nocase

    condition:
        (2 of ($notif*)) or
        (2 of ($popup*) and 1 of ($chain*)) or
        (1 of ($popup*) and 1 of ($chain*) and 1 of ($evade*))
}
