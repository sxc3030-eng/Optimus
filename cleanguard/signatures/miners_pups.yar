/*
    CleanGuard Pro - Cryptominer & PUP Detection Rules
    Signatures for cryptocurrency miners and potentially unwanted programs
    Last Updated: 2026-03-24
*/

rule CryptoMiner_Stratum
{
    meta:
        description = "Detects Stratum mining protocol usage and mining pool connections"
        severity = "high"
        author = "CleanGuard Pro"
        date = "2026-03-24"
        category = "cryptominer"

    strings:
        $proto1 = "stratum+tcp://" ascii wide nocase
        $proto2 = "stratum+ssl://" ascii wide nocase
        $proto3 = "stratum2+tcp://" ascii wide nocase
        $pool1 = "pool.minexmr.com" ascii wide nocase
        $pool2 = "pool.supportxmr.com" ascii wide nocase
        $pool3 = "xmrpool.eu" ascii wide nocase
        $pool4 = "mine.moneropool.com" ascii wide nocase
        $pool5 = "pool.hashvault.pro" ascii wide nocase
        $pool6 = "monerohash.com" ascii wide nocase
        $pool7 = "nanopool.org" ascii wide nocase
        $pool8 = "2miners.com" ascii wide nocase
        $pool9 = "f2pool.com" ascii wide nocase
        $pool10 = "ethermine.org" ascii wide nocase
        $pool11 = "nicehash.com" ascii wide nocase
        $pool12 = "unmineable.com" ascii wide nocase
        $json1 = "mining.subscribe" ascii wide nocase
        $json2 = "mining.authorize" ascii wide nocase
        $json3 = "mining.submit" ascii wide nocase
        $json4 = "mining.notify" ascii wide nocase
        $rate1 = "hashrate" ascii wide nocase
        $rate2 = "hash_rate" ascii wide nocase
        $rate3 = "H/s" ascii wide
        $rate4 = "KH/s" ascii wide
        $rate5 = "MH/s" ascii wide
        $rate6 = "GH/s" ascii wide

    condition:
        any of ($proto*) or 2 of ($pool*) or 2 of ($json*) or (1 of ($pool*) and 1 of ($rate*))
}

rule CryptoMiner_XMRig
{
    meta:
        description = "Detects XMRig cryptocurrency miner binaries and configuration"
        severity = "high"
        author = "CleanGuard Pro"
        date = "2026-03-24"
        category = "cryptominer"

    strings:
        $xmrig1 = "xmrig" ascii wide nocase
        $xmrig2 = "XMRig" ascii wide
        $xmrig3 = "xmr-stak" ascii wide nocase
        $xmrig4 = "RandomX" ascii wide
        $xmrig5 = "CryptoNight" ascii wide
        $xmrig6 = "rx/0" ascii wide
        $xmrig7 = "cn/r" ascii wide
        $xmrig8 = "argon2" ascii wide nocase
        $addr1 = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/ ascii wide
        $cfg1 = "\"algo\"" ascii wide
        $cfg2 = "\"url\"" ascii wide
        $cfg3 = "\"user\"" ascii wide
        $cfg4 = "\"pass\"" ascii wide
        $cfg5 = "\"donate-level\"" ascii wide nocase
        $cfg6 = "\"cpu\"" ascii wide
        $cfg7 = "\"opencl\"" ascii wide
        $cfg8 = "\"cuda\"" ascii wide
        $cfg9 = "\"threads\"" ascii wide
        $cfg10 = "\"pools\"" ascii wide
        $opt1 = "--donate-level" ascii wide nocase
        $opt2 = "--coin" ascii wide nocase
        $opt3 = "--algo" ascii wide nocase
        $opt4 = "--url" ascii wide nocase

    condition:
        2 of ($xmrig*) or ($addr1 and 2 of ($cfg*)) or (1 of ($xmrig*) and 2 of ($cfg*)) or 3 of ($opt*)
}

rule PUP_BrowserHijacker
{
    meta:
        description = "Detects browser hijacker behavior - homepage and search engine modification"
        severity = "medium"
        author = "CleanGuard Pro"
        date = "2026-03-24"
        category = "pup"

    strings:
        $reg1 = "Start Page" ascii wide nocase
        $reg2 = "Search Page" ascii wide nocase
        $reg3 = "Default_Search_URL" ascii wide nocase
        $reg4 = "SearchScopes" ascii wide nocase
        $reg5 = "Software\\Microsoft\\Internet Explorer\\Main" ascii wide nocase
        $reg6 = "Software\\Microsoft\\Internet Explorer\\Search" ascii wide nocase
        $chrome1 = "\\Google\\Chrome\\User Data\\Default\\Preferences" ascii wide nocase
        $chrome2 = "\\Google\\Chrome\\User Data\\Default\\Secure Preferences" ascii wide nocase
        $chrome3 = "chrome.exe" ascii wide nocase
        $ff1 = "\\Mozilla\\Firefox\\Profiles" ascii wide nocase
        $ff2 = "prefs.js" ascii wide nocase
        $ff3 = "browser.startup.homepage" ascii wide nocase
        $ff4 = "browser.search.defaultenginename" ascii wide nocase
        $ff5 = "keyword.URL" ascii wide nocase
        $edge1 = "\\Microsoft\\Edge\\User Data\\Default\\Preferences" ascii wide nocase
        $api1 = "RegSetValueEx" ascii wide nocase
        $api2 = "RegOpenKeyEx" ascii wide nocase
        $api3 = "RegCreateKeyEx" ascii wide nocase
        $home1 = "homepage" ascii wide nocase
        $home2 = "default_search_provider" ascii wide nocase
        $home3 = "newtab" ascii wide nocase

    condition:
        (2 of ($reg*) and 1 of ($api*)) or
        (1 of ($chrome*) and 1 of ($home*)) or
        (2 of ($ff*)) or
        (1 of ($edge1, $chrome1, $chrome2) and 1 of ($api*))
}

rule PUP_Adware_Injector
{
    meta:
        description = "Detects adware injection techniques - ad insertion and popup generation"
        severity = "medium"
        author = "CleanGuard Pro"
        date = "2026-03-24"
        category = "pup"

    strings:
        $inject1 = "document.createElement('iframe')" ascii wide nocase
        $inject2 = "document.createElement(\"iframe\")" ascii wide nocase
        $inject3 = "innerHTML" ascii wide nocase
        $inject4 = "insertBefore" ascii wide nocase
        $inject5 = "appendChild" ascii wide nocase
        $inject6 = "document.write" ascii wide nocase
        $ad1 = "ad_banner" ascii wide nocase
        $ad2 = "ad_popup" ascii wide nocase
        $ad3 = "advert" ascii wide nocase
        $ad4 = "sponsored" ascii wide nocase
        $ad5 = "clicktrack" ascii wide nocase
        $ad6 = "doubleclick" ascii wide nocase
        $popup1 = "window.open(" ascii wide nocase
        $popup2 = "window.showModalDialog" ascii wide nocase
        $popup3 = "showModelessDialog" ascii wide nocase
        $popup4 = "popunder" ascii wide nocase
        $popup5 = "popupWindow" ascii wide nocase
        $iframe1 = "iframe" ascii wide nocase
        $iframe2 = "visibility:hidden" ascii wide nocase
        $iframe3 = "display:none" ascii wide nocase
        $iframe4 = "width:0" ascii wide nocase
        $iframe5 = "height:0" ascii wide nocase

    condition:
        (2 of ($inject*) and 1 of ($ad*)) or
        (1 of ($inject*) and 2 of ($popup*)) or
        (1 of ($inject*) and 2 of ($iframe*) and 1 of ($ad*))
}
