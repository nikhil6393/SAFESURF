"""
Feature Extractor for URL Malware & Phishing Detection v3.5
Extracts 38 refined numerical, structural, lexical, and statistical signals from URLs.
Features multi-part TLD parsing, precision brand matching, and calibrated DGA entropy.
"""

import re
import math
from urllib.parse import urlparse, parse_qs

SUSPICIOUS_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work',
    'click', 'link', 'loan', 'download', 'stream', 'online',
    'site', 'best', 'win', 'party', 'bid', 'icu', 'buzz',
    'live', 'fun', 'space', 'world', 'mobi', 'club',
    'rest', 'guru', 'tokyo', 'vip', 'men', 'science', 'gdn',
    'monster', 'surf', 'cam', 'quest', 'cfd', 'sbs'
}

MULTI_TLDS = {
    'co.uk', 'co.in', 'com.au', 'com.br', 'co.jp', 'co.nz', 'co.za',
    'com.mx', 'com.sg', 'com.tr', 'com.tw', 'com.hk', 'com.ar',
    'gov.in', 'gov.uk', 'nic.in', 'ac.in', 'edu.au', 'org.uk',
    'net.au', 'org.au', 'gc.ca', 'mil.uk', 'ne.jp', 'or.jp',
    'ac.uk', 'ac.jp', 'go.jp', 'gen.in', 'res.in', 'ind.in',
    'co.kr', 'com.co', 'com.pe', 'com.pk', 'com.ng', 'com.eg'
}

SENSITIVE_KEYWORDS = [
    'login', 'verify', 'account', 'secure', 'update', 'bank', 'wallet',
    'signin', 'support', 'service', 'billing', 'confirm', 'validation',
    'auth', 'portal', 'ebayisapi', 'paypal', 'webscr', 'wp-admin',
    'password', 'credential', 'recover', 'suspend', 'locked', 'unusual',
    'access', 'admin', 'checkpoint', 'identity', 'renew', 'security',
    'session', 'banking', 'reclaim', 'verification', 'authenticate',
    'airdrops', 'giveaway', 'metamask', 'seedphrase', 'secretphrase'
]

TRUSTED_BRANDS = [
    'google', 'microsoft', 'apple', 'icloud', 'amazon', 'facebook',
    'instagram', 'twitter', 'linkedin', 'netflix', 'paypal', 'binance',
    'coinbase', 'blockchain', 'adobe', 'steam', 'dropbox', 'yahoo',
    'outlook', 'office365', 'chase', 'wellsfargo', 'citibank', 'bankofamerica',
    'github', 'gitlab', 'stackoverflow', 'wikipedia', 'youtube', 'openai',
    'chatgpt', 'spotify', 'slack', 'zoom', 'reddit', 'stripe', 'shopify'
]

OFFICIAL_BRAND_DOMAINS = {
    'google.com', 'microsoft.com', 'apple.com', 'icloud.com',
    'amazon.com', 'facebook.com', 'instagram.com', 'twitter.com',
    'linkedin.com', 'netflix.com', 'paypal.com', 'binance.com',
    'coinbase.com', 'adobe.com', 'steampowered.com', 'dropbox.com',
    'yahoo.com', 'live.com', 'microsoftonline.com', 'office.com',
    'outlook.com', 'chase.com', 'wellsfargo.com', 'citibank.com',
    'bankofamerica.com', 'github.com', 'stackoverflow.com',
    'wikipedia.org', 'reddit.com', 'youtube.com', 'bing.com',
    'openai.com', 'chatgpt.com', 'medium.com', 'nih.gov', 'cnn.com', 'bbc.com',
    'nytimes.com', 'reuters.com', 'theguardian.com', 'europa.eu',
    'react.dev', 'tailwindcss.com', 'huggingface.co', 'notion.so'
}

URL_SHORTENERS = {
    'bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'is.gd',
    'buff.ly', 'bit.do', 'ow.ly', 'rebrand.ly', 'short.link',
    'cutt.ly', 'rb.gy', 'tiny.cc', 'clck.ru', 'qr.net', 'bc.vc'
}

HOMOGLYPH_MAP = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
    '6': 'g', '7': 't', '8': 'b', '9': 'q',
    '@': 'a', '$': 's', '!': 'i'
}

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    length = len(s)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return float(entropy)

def consonant_and_vowel_ratio(s: str):
    alpha = [c.lower() for c in s if c.isalpha()]
    if not alpha:
        return 0.0, 0.0
    vowels = sum(1 for c in alpha if c in 'aeiou')
    consonants = len(alpha) - vowels
    return float(consonants / len(alpha)), float(vowels / len(alpha))

def max_consecutive_consonants(s: str) -> int:
    max_len = 0
    current_len = 0
    for c in s.lower():
        if c.isalpha() and c not in 'aeiou':
            current_len += 1
            if current_len > max_len:
                max_len = current_len
        else:
            current_len = 0
    return max_len

def normalize_homoglyphs(s: str) -> str:
    res = []
    for c in s.lower():
        res.append(HOMOGLYPH_MAP.get(c, c))
    return ''.join(res)

def decompose_hostname(hostname: str):
    parts = hostname.split('.')
    if len(parts) <= 1:
        return {'parts': parts, 'tld': '', 'sld': hostname, 'subdomains': [], 'registered_domain': hostname}
    
    # Check multi-level TLDs (e.g., google.co.in)
    if len(parts) >= 3:
        last_two = f"{parts[-2]}.{parts[-1]}"
        if last_two in MULTI_TLDS:
            tld = last_two
            sld = parts[-3]
            subdomains = parts[:-3]
            return {'parts': parts, 'tld': tld, 'sld': sld, 'subdomains': subdomains, 'registered_domain': f"{sld}.{tld}"}
            
    tld = parts[-1]
    sld = parts[-2]
    subdomains = parts[:-2]
    return {'parts': parts, 'tld': tld, 'sld': sld, 'subdomains': subdomains, 'registered_domain': f"{sld}.{tld}"}

def extract_features_from_url(url: str) -> dict:
    url_str = str(url).strip()
    if not url_str:
        url_str = 'about:blank'
    
    parsed_input = url_str if ('://' in url_str) else ('http://' + url_str)
    
    try:
        parsed = urlparse(parsed_input)
        hostname = (parsed.hostname or '').lower()
        pathname = parsed.path or ''
        query = parsed.query or ''
    except Exception:
        hostname = url_str.split('/')[0].lower()
        pathname = '/'
        query = ''

    full_url = url_str.lower()
    full_path = f"{hostname}{pathname}{('?' + query) if query else ''}".lower()

    # Precise Hostname decomposition
    decomp = decompose_hostname(hostname)
    tld = decomp['tld']
    sld = decomp['sld']
    subdomains = decomp['subdomains']
    reg_domain = decomp['registered_domain']

    # Features extraction
    url_len = len(url_str)
    host_len = len(hostname)
    path_len = len(pathname)
    query_len = len(query)

    num_dots = full_url.count('.')
    num_hyphens = full_url.count('-')
    num_underscores = full_url.count('_')
    num_slashes = full_url.count('/')
    num_question_marks = full_url.count('?')
    num_equal_signs = full_url.count('=')
    num_at_symbols = full_url.count('@')
    num_ampersands = full_url.count('&')
    num_percent_symbols = full_url.count('%')

    digits_url = sum(c.isdigit() for c in full_url)
    digits_host = sum(c.isdigit() for c in hostname)
    ratio_digits_url = digits_url / max(1, url_len)
    ratio_digits_host = digits_host / max(1, host_len)

    hostname_core = sld if sld else hostname.replace('.', '')
    entropy_url = shannon_entropy(full_url)
    entropy_host = shannon_entropy(hostname_core)
    entropy_path = shannon_entropy(pathname)

    consonant_ratio, vowel_ratio = consonant_and_vowel_ratio(hostname_core)
    longest_consec_consonants = max_consecutive_consonants(hostname_core)

    subdomain_depth = len(subdomains)
    sld_len = len(sld)
    sld_is_num = 1 if (sld and sld.isdigit()) else 0

    is_ip = 1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname) else 0
    has_punycode = 1 if 'xn--' in hostname else 0
    has_susp_tld = 1 if tld in SUSPICIOUS_TLDS else 0

    has_shortener = 1 if (hostname in URL_SHORTENERS or reg_domain in URL_SHORTENERS) else 0

    has_double_ext = 1 if re.search(r'\.(exe|zip|rar|gz|bat|scr|msi|ps1|vbs|sh)\.(exe|zip|rar|gz|bat|scr|msi|ps1|vbs|sh)$', full_url) else 0

    # Phishing keywords count
    num_sensitive_kws = sum(1 for kw in SENSITIVE_KEYWORDS if kw in full_path)

    # Precise Brand impersonation & Whitelist evaluation
    is_trusted = False
    if reg_domain in OFFICIAL_BRAND_DOMAINS or hostname in OFFICIAL_BRAND_DOMAINS:
        is_trusted = True
    elif sld in TRUSTED_BRANDS and len(subdomains) <= 2 and tld not in SUSPICIOUS_TLDS:
        # Legitimate brand ownership on standard TLDs (e.g. google.co.in, amazon.in, apple.co.uk)
        is_trusted = True
    else:
        for off in OFFICIAL_BRAND_DOMAINS:
            if hostname == off or hostname.endswith('.' + off):
                is_trusted = True
                break

    brand_score = 0
    is_homoglyph = False

    if not is_trusted:
        norm_host = normalize_homoglyphs(hostname)
        norm_sld = normalize_homoglyphs(sld)

        for brand in TRUSTED_BRANDS:
            # 1. Homoglyph visual substitution (e.g., g00gle.com, paypa1.com)
            if brand in norm_sld and brand != sld:
                brand_score = 1
                is_homoglyph = True
                break
            # 2. Brand name appearing in unofficial domain / subdomain chain
            elif brand in hostname:
                if sld != brand:
                    brand_score = 1
                    break

    is_https = 1 if url_str.startswith('https://') else 0
    has_port = 1 if bool(parsed.port) else 0
    
    suspicious_port = 0
    try:
        if parsed.port and parsed.port not in (80, 443):
            suspicious_port = 1
    except Exception:
        # Invalid port is suspicious
        suspicious_port = 1

    has_hex = 1 if bool(re.search(r'%[0-9a-fA-F]{2}', full_url)) else 0

    path_segments = [s for s in pathname.split('/') if s]
    max_path_seg_len = max((len(s) for s in path_segments), default=0)
    
    try:
        query_params = parse_qs(query)
        param_count = len(query_params)
    except Exception:
        param_count = query.count('&') + (1 if query else 0)

    has_redirect_param = 1 if any(k.lower() in {'redirect', 'url', 'next', 'return', 'goto', 'link', 'dest', 'redir', 'target'} for k in query.split('&')) else 0

    return {
        'url_length': url_len,
        'host_length': host_len,
        'path_length': path_len,
        'query_length': query_len,
        'num_dots': num_dots,
        'num_hyphens': num_hyphens,
        'num_underscores': num_underscores,
        'num_slashes': num_slashes,
        'num_question_marks': num_question_marks,
        'num_equal_signs': num_equal_signs,
        'num_at_symbols': num_at_symbols,
        'num_ampersands': num_ampersands,
        'num_percent_symbols': num_percent_symbols,
        'num_digits_url': digits_url,
        'num_digits_host': digits_host,
        'ratio_digits_url': round(ratio_digits_url, 4),
        'ratio_digits_host': round(ratio_digits_host, 4),
        'entropy_url': round(entropy_url, 4),
        'entropy_host': round(entropy_host, 4),
        'entropy_path': round(entropy_path, 4),
        'consonant_ratio_host': round(consonant_ratio, 4),
        'vowel_ratio_host': round(vowel_ratio, 4),
        'subdomain_depth': subdomain_depth,
        'sld_length': sld_len,
        'sld_is_numeric': sld_is_num,
        'is_ip_address': is_ip,
        'has_punycode': has_punycode,
        'has_suspicious_tld': has_susp_tld,
        'has_url_shortener': has_shortener,
        'has_double_extension': has_double_ext,
        'num_sensitive_keywords': num_sensitive_kws,
        'brand_impersonation_score': brand_score,
        'is_https': is_https,
        'has_port': has_port,
        'has_hex_encoding': has_hex,
        'max_path_segment_len': max_path_seg_len,
        'param_count': param_count,
        'has_redirect_param': has_redirect_param,
        'is_trusted_official': is_trusted,
        'is_homoglyph_attack': is_homoglyph,
        'longest_consec_consonants': longest_consec_consonants,
        'has_suspicious_port': suspicious_port
    }

FEATURE_NAMES = [
    'url_length', 'host_length', 'path_length', 'query_length',
    'num_dots', 'num_hyphens', 'num_underscores', 'num_slashes',
    'num_question_marks', 'num_equal_signs', 'num_at_symbols',
    'num_ampersands', 'num_percent_symbols', 'num_digits_url',
    'num_digits_host', 'ratio_digits_url', 'ratio_digits_host',
    'entropy_url', 'entropy_host', 'entropy_path',
    'consonant_ratio_host', 'vowel_ratio_host', 'subdomain_depth',
    'sld_length', 'sld_is_numeric', 'is_ip_address', 'has_punycode',
    'has_suspicious_tld', 'has_url_shortener', 'has_double_extension',
    'num_sensitive_keywords', 'brand_impersonation_score',
    'is_https', 'has_port', 'has_hex_encoding',
    'max_path_segment_len', 'param_count', 'has_redirect_param',
    'longest_consec_consonants', 'has_suspicious_port'
]

def extract_feature_vector(url: str) -> list:
    f_dict = extract_features_from_url(url)
    return [f_dict[name] for name in FEATURE_NAMES]
