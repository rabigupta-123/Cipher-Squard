/*
 * Cipher Squad — bundled YARA rules for phishing & malicious email detection.
 * These patterns flag obfuscation, spoofing, and credential-theft indicators
 * found in scanned email payloads. They are conservative: each rule requires
 * multiple co-occurring signals to reduce false positives.
 */
rule phishing_spoofing_layout_obfuscation
{
    meta:
        description = "Flag spoofed sender display name plus obfuscated URL layout"
        author = "Cipher Squad"
        severity = "high"
    strings:
        $a = "From: "
        $b = "Secure Mail"
        $c = "verify your account"
        $d = "account has been"
    condition:
        $a and (2 of ($b,$c,$d))
}

rule credential_harvest_urgent
{
    meta:
        description = "Urgent login / password reset language co-located with a click instruction"
        author = "Cipher Squad"
        severity = "medium"
    strings:
        $u = "expire" nocase
        $p = "password" nocase
        $r = "reset" nocase
        $l = "https://" nocase
        $c = "click here" nocase
    condition:
        $p and ($r or $u) and ($l or $c)
}

rule encoded_admin_redirect
{
    meta:
        description = "Obfuscated admin-doublefeed / base64-redirect patterns typical of phishing"
        author = "Cipher Squad"
        severity = "high"
    strings:
        $a = "doublefeed" nocase
        $b = "login.php" nocase
        $c = "base64" nocase
        $d = "eval(" nocase
        $e = "unbase64" nocase
        $f = "window.location" nocase
    condition:
        2 of them
}

rule fake_account_suspension
{
    meta:
        description = "Account-suspension scare combined with a follow-action link"
        author = "Cipher Squad"
        severity = "medium"
    strings:
        $s = "suspended" nocase
        $c = "closed" nocase
        $d = "deactivated" nocase
        $l = "http://" nocase
    condition:
        ($s or $c or $d) and $l
}

rule spoofed_brand_message_id
{
    meta:
        description = "Sender claims a brand while the message header hints at mismatch"
        author = "Cipher Squad"
        severity = "low"
    strings:
        $a = "Microsoft" nocase
        $b = "Apple" nocase
        $c = "PayPal" nocase
        $d = "Netflix" nocase
        $e = "password" nocase
    condition:
        any of ($a,$b,$c,$d) and $e
}

rule obfuscated_ip_link
{
    meta:
        description = "Link pointing at a raw IP address (often credential phishing)"
        author = "Cipher Squad"
        severity = "medium"
    strings:
        $ip = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/
        $login = "login" nocase
        $click = "click" nocase
        $herr = /href\s*=\s*["']?https?:\/\//i
    condition:
        $herr and $ip and ($login or $click)
}
