"""
Comprehensive Dataset Builder & Generator v3.5
Builds a high-diversity, real-world balanced dataset of Safe, Phishing, Malware, and Defacement URLs.
Includes full ccTLD representation, modern web frameworks, developer docs, and modern phishing vectors.
"""

import os
import csv
import random

def build_dataset(output_path='ml/data/training_dataset.csv', target_total=6000):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    existing_rows = []
    sample_csv = 'backend/data/dataset.csv'
    if os.path.exists(sample_csv):
        with open(sample_csv, mode='r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            for r in reader:
                u = r.get('url', '').strip()
                l = r.get('label', '').strip().lower()
                t = r.get('type', 'benign').strip().lower()
                if u and l in {'safe', 'malicious', 'suspicious'}:
                    existing_rows.append({'url': u, 'label': l, 'type': t})

    benign_domains = [
        # Major global brands & search
        'google.com', 'google.co.in', 'google.co.uk', 'google.de', 'google.fr', 'google.co.jp',
        'wikipedia.org', 'en.wikipedia.org', 'github.com', 'microsoft.com', 'youtube.com',
        'amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.de', 'amazon.co.jp',
        'apple.com', 'apple.co.uk', 'apple.in', 'linkedin.com', 'reddit.com', 'stackoverflow.com',
        'cloudflare.com', 'medium.com', 'nih.gov', 'cdc.gov', 'stanford.edu', 'mit.edu', 'iitd.ac.in',
        'nytimes.com', 'bbc.co.uk', 'theguardian.com', 'reuters.com', 'cnn.com', 'theverge.com',
        'spotify.com', 'netflix.com', 'dropbox.com', 'adobe.com', 'gitlab.com', 'bitbucket.org',
        'archive.org', 'npmjs.com', 'pypi.org', 'docker.com', 'kaggle.com', 'huggingface.co',
        'docs.python.org', 'developer.mozilla.org', 'w3schools.com', 'coursera.org', 'udemy.com',
        'arxiv.org', 'nature.com', 'sciencedirect.com', 'ieee.org', 'springer.com',
        'booking.com', 'airbnb.com', 'stripe.com', 'shopify.com', 'salesforce.com', 'hubspot.com',
        'slack.com', 'zoom.us', 'notion.so', 'trello.com', 'asana.com', 'figma.com', 'canva.com',
        'atlassian.com', 'jira.com', 'confluence.com', 'zendesk.com', 'intercom.com',
        'react.dev', 'vuejs.org', 'angular.io', 'tailwindcss.com', 'nextjs.org', 'nodejs.org',
        'chatgpt.com', 'openai.com', 'anthropic.com', 'news.ycombinator.com',
        'gov.uk', 'india.gov.in', 'europa.eu', 'un.org', 'who.int', 'nasa.gov',
        'usps.com', 'fedex.com', 'ups.com', 'dhl.com', 'target.com', 'walmart.com',
        'bestbuy.com', 'homedepot.com', 'costco.com', 'ikea.com', 'etsy.com', 'ebay.com', 'ebay.co.uk'
    ]

    benign_paths = [
        '', '/', '/about-us', '/privacy-policy', '/terms-of-service', '/contact',
        '/help/center/faq', '/docs/v2/api/reference/get-user', '/wiki/Machine_learning',
        '/products/electronics/headphones/wireless-noise-cancelling-model-400',
        '/blog/2024/05/12/advances-in-cybersecurity-and-threat-detection',
        '/repo/owner/project-v3/tree/main/src/components/ui/button.tsx',
        '/questions/8492048/how-to-optimize-random-forest-hyperparameters',
        '/search?q=open+source+machine+learning+libraries&page=3&sort=relevance',
        '/article/view/10.1109/TIFS.2023.3298412/fulltext',
        '/user/profile/settings/preferences?theme=dark&lang=en-US',
        '/courses/deep-learning-specialization/lecture/backpropagation-overview',
        '/downloads/v1.4.2/windows-x64-installer.msi',
        '/images/gallery/nature/forest-sunrise-4k-high-resolution.jpg',
        '/audio/podcasts/episode-42-future-of-artificial-intelligence.mp3',
        '/api/v1/healthcheck?timestamp=1715428900&service=auth-gateway',
        '/dp/B08N5WRWNW', '/store', '/in/user-name', '/spaces'
    ]

    phishing_brands = [
        'paypal', 'apple', 'microsoft', 'google', 'chase', 'wellsfargo',
        'bankofamerica', 'citibank', 'netflix', 'amazon', 'facebook',
        'instagram', 'binance', 'coinbase', 'metamask', 'blockchain',
        'icloud', 'outlook', 'office365', 'adobe', 'steam', 'dhl', 'fedex', 'chase-bank'
    ]

    phishing_keywords = [
        'login', 'verify', 'account-update', 'secure-banking', 'signin-confirm',
        'auth-checkpoint', 'unlock-suspended-account', 'validation-portal',
        'billing-information-review', 'password-reset-request', 'identity-check',
        'wallet-connect-airdrop', 'claim-reward-bonus', 'security-alert-center'
    ]

    suspicious_tlds = [
        'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'work', 'click', 'link',
        'loan', 'download', 'stream', 'online', 'site', 'best', 'win', 'party',
        'bid', 'icu', 'buzz', 'live', 'fun', 'space', 'club', 'vip', 'rest',
        'monster', 'cam', 'quest', 'cfd', 'sbs'
    ]

    malware_extensions = [
        '.exe', '.scr', '.vbs', '.bat', '.ps1', '.msi', '.zip.exe',
        '.pdf.exe', '.invoice.scr', '.order-spec.rar.exe', '.sh'
    ]

    all_dataset = list(existing_rows)
    seen_urls = set(r['url'] for r in existing_rows)

    random.seed(42)

    # 1. Generate Safe / Benign URLs (High Diversity)
    while len([r for r in all_dataset if r['label'] == 'safe']) < target_total // 2:
        dom = random.choice(benign_domains)
        proto = 'https://' if random.random() > 0.10 else 'http://'
        sub = ''
        if random.random() > 0.5:
            sub = random.choice(['www.', 'blog.', 'docs.', 'api.', 'support.', 'mail.', 'app.', 'dev.', 'en.'])
        path = random.choice(benign_paths)
        if random.random() > 0.5 and path:
            path += f"?ref={random.randint(100, 99999)}&utm_source=newsletter"
        
        full_u = f"{proto}{sub}{dom}{path}"
        if full_u not in seen_urls:
            seen_urls.add(full_u)
            all_dataset.append({'url': full_u, 'label': 'safe', 'type': 'benign'})

    # 2. Generate Phishing URLs
    while len([r for r in all_dataset if r['type'] == 'phishing']) < target_total // 4:
        brand = random.choice(phishing_brands)
        kw = random.choice(phishing_keywords)
        tld = random.choice(suspicious_tlds + ['com', 'net', 'org', 'info', 'cc'])
        
        style = random.randint(1, 6)
        if style == 1:
            # Subdomain chain: e.g., paypal.com.verify-user.security-checkpoint.xyz
            u = f"http://{brand}.com.{kw}.user-auth.{tld}/index.php?token={random.randint(100000, 999999)}"
        elif style == 2:
            # Hyphenated brand-keyword: e.g., appleid-verify-account-security.top
            u = f"https://{brand}-{kw}-{random.randint(10, 99)}.{tld}/signin.html"
        elif style == 3:
            # Homoglyph spoofing: e.g., micr0soft-security-center.xyz, paypa1.com
            homo_brand = brand.replace('o', '0').replace('l', '1').replace('e', '3').replace('a', '@')
            u = f"http://{homo_brand}-{kw}.{tld}/login.php?client_id={random.randint(1000, 9999)}"
        elif style == 4:
            # Deep path phishing
            u = f"http://service-portal-node{random.randint(1, 99)}.{tld}/{brand}/login/webscr?cmd=_login-run&session={random.randint(1000000, 9999999)}"
        elif style == 5:
            # Open redirect phishing with @ symbol
            u = f"http://secure-login-portal.{tld}/@verify/account?dest=http://fake-{brand}-login.{tld}/credentials"
        else:
            # Numeric IP phishing
            ip = f"{random.randint(45, 220)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            u = f"http://{ip}/{brand}/{kw}/index.htm"

        if u not in seen_urls:
            seen_urls.add(u)
            all_dataset.append({'url': u, 'label': 'malicious', 'type': 'phishing'})

    # 3. Generate Malware / C2 / Exploit URLs
    while len([r for r in all_dataset if r['type'] == 'malware']) < target_total // 6:
        tld = random.choice(suspicious_tlds + ['ru', 'su', 'cc', 'top', 'to', 'is'])
        # Real DGA random domain with high consonant density
        dga_chars = "bcdfghjklmnpqrstvwxyz0123456789"
        dga = ''.join(random.choice(dga_chars) for _ in range(random.randint(12, 22)))
        ext = random.choice(malware_extensions)
        
        style = random.randint(1, 4)
        if style == 1:
            u = f"http://{dga}.{tld}/payload/drop_{random.randint(100, 999)}{ext}"
        elif style == 2:
            ip = f"{random.randint(45, 220)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            port = random.choice([8080, 4444, 1337, 8888, 9001, 3128, 8000])
            u = f"http://{ip}:{port}/botnet/gate.php?guid={dga[:8]}&action=beacon"
        elif style == 3:
            u = f"https://{dga}.{tld}/updates/windows-security-hotfix-kb{random.randint(10000, 99999)}{ext}"
        else:
            u = f"http://{dga}.{tld}/api/stealer/exfiltrate?data=base64payload_{random.randint(10000, 99999)}"

        if u not in seen_urls:
            seen_urls.add(u)
            all_dataset.append({'url': u, 'label': 'malicious', 'type': 'malware'})

    # 4. Generate Defacement / Web Attack URLs
    while len(all_dataset) < target_total:
        dom = f"vulnerable-site-{random.randint(1, 999)}.{random.choice(['com', 'org', 'net', 'co.uk', 'de', 'br', 'in'])}"
        attack_paths = [
            f"/index.php?id=1'+UNION+SELECT+null,username,password+FROM+users--",
            f"/search.php?q=<script>alert('HACKED_BY_TEAM_{random.randint(1, 99)}')</script>",
            f"/administrator/components/com_content/upload.php?file=backdoor.php%00.jpg",
            f"/forum/viewtopic.php?t=123&highlight=%2527%252Ephpinfo%2528%2529%252E%2527",
            f"/hacked.html",
            f"/deface/owned_by_crew.htm?defacer=ghost_rider_{random.randint(1, 99)}"
        ]
        u = f"http://www.{dom}{random.choice(attack_paths)}"
        if u not in seen_urls:
            seen_urls.add(u)
            all_dataset.append({'url': u, 'label': 'suspicious', 'type': 'defacement'})

    random.shuffle(all_dataset)

    with open(output_path, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['url', 'label', 'type'])
        writer.writeheader()
        writer.writerows(all_dataset)

    stats = {}
    for r in all_dataset:
        stats[r['label']] = stats.get(r['label'], 0) + 1
        stats[r['type']] = stats.get(r['type'], 0) + 1

    print(f"Successfully compiled dataset with {len(all_dataset)} entries to {output_path}")
    print("Dataset Distribution:", stats)
    return output_path

if __name__ == '__main__':
    build_dataset()
