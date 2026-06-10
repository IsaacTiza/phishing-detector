import re
import socket
import requests
import whois
import dns.resolver
from bs4 import BeautifulSoup
from datetime import datetime
from urllib.parse import urlparse

# ─── HELPERS ────────────────────────────────────────────

def get_domain(url):
    try:
        return urlparse(url).netloc
    except:
        return ""

def fetch_page(url):
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        return response
    except:
        return None

def get_whois(domain):
    try:
        return whois.whois(domain)
    except:
        return None

# ─── ADDRESS BAR FEATURES ───────────────────────────────

def having_IP_Address(url):
    # Check if URL uses IP address instead of domain name
    ip_pattern = re.compile(
        r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])'
    )
    match = re.search(ip_pattern, url)
    return -1 if match else 1

def URL_Length(url):
    length = len(url)
    if length < 54:
        return 1
    elif length <= 75:
        return 0
    else:
        return -1

def Shortining_Service(url):
    shorteners = [
        'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
        'is.gd', 'buff.ly', 'adf.ly', 'short.link'
    ]
    domain = get_domain(url).lower()
    return -1 if any(s in domain for s in shorteners) else 1

def having_At_Symbol(url):
    return -1 if '@' in url else 1

def double_slash_redirecting(url):
    # Check if // appears after position 7 (after http://)
    pos = url.find('//', 7)
    return -1 if pos > 7 else 1

def Prefix_Suffix(url):
    domain = get_domain(url)
    return -1 if '-' in domain else 1

def having_Sub_Domain(url):
    domain = get_domain(url)
    # Remove www.
    if domain.startswith('www.'):
        domain = domain[4:]
    dot_count = domain.count('.')
    if dot_count == 1:
        return 1
    elif dot_count == 2:
        return 0
    else:
        return -1

def SSLfinal_State(url, response):
    # Check if HTTPS and valid
    if url.startswith('https'):
        try:
            domain = get_domain(url)
            w = get_whois(domain)
            if w and w.expiration_date:
                exp = w.expiration_date
                if isinstance(exp, list):
                    exp = exp[0]
                age = (exp - datetime.now()).days
                if age > 365:
                    return 1
            return 0
        except:
            return 0
    return -1

def Domain_registeration_length(url):
    try:
        domain = get_domain(url)
        w = get_whois(domain)
        if w and w.expiration_date and w.creation_date:
            exp = w.expiration_date
            cre = w.creation_date
            if isinstance(exp, list): exp = exp[0]
            if isinstance(cre, list): cre = cre[0]
            length = (exp - cre).days
            return 1 if length > 365 else -1
    except:
        pass
    return -1

def Favicon(url, soup, domain):
    try:
        for link in soup.find_all('link', rel='shortcut icon'):
            href = link.get('href', '')
            if domain not in href and href.startswith('http'):
                return -1
        return 1
    except:
        return 1

def port(url):
    try:
        parsed = urlparse(url)
        port_num = parsed.port
        suspicious_ports = [21, 22, 23, 445, 1433, 1521, 3306, 3389]
        if port_num and port_num in suspicious_ports:
            return -1
        return 1
    except:
        return 1

def HTTPS_token(url):
    domain = get_domain(url)
    return -1 if 'https' in domain.lower() else 1

# ─── CONTENT BASED FEATURES ─────────────────────────────

def Request_URL(url, soup, domain):
    try:
        tags = soup.find_all(['img', 'video', 'audio', 'script'])
        total = len(tags)
        if total == 0:
            return 1
        external = 0
        for tag in tags:
            src = tag.get('src', '')
            if src.startswith('http') and domain not in src:
                external += 1
        ratio = external / total
        if ratio < 0.22:
            return 1
        elif ratio < 0.61:
            return 0
        else:
            return -1
    except:
        return 1

def URL_of_Anchor(url, soup, domain):
    try:
        anchors = soup.find_all('a')
        total = len(anchors)
        if total == 0:
            return 1
        unsafe = 0
        for a in anchors:
            href = a.get('href', '')
            if href in ['#', '#content', '#skip', ''] or 'javascript' in href.lower():
                unsafe += 1
            elif href.startswith('http') and domain not in href:
                unsafe += 1
        ratio = unsafe / total
        if ratio < 0.31:
            return 1
        elif ratio < 0.67:
            return 0
        else:
            return -1
    except:
        return 1

def Links_in_tags(url, soup, domain):
    try:
        tags = soup.find_all(['meta', 'script', 'link'])
        total = len(tags)
        if total == 0:
            return 1
        external = 0
        for tag in tags:
            src = tag.get('src', '') or tag.get('href', '')
            if src.startswith('http') and domain not in src:
                external += 1
        ratio = external / total
        if ratio < 0.17:
            return 1
        elif ratio < 0.81:
            return 0
        else:
            return -1
    except:
        return 1

def SFH(url, soup, domain):
    try:
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action', '')
            if action in ['', 'about:blank']:
                return -1
            if action.startswith('http') and domain not in action:
                return 0
        return 1
    except:
        return 1

def Submitting_to_email(url, soup):
    try:
        page_text = str(soup)
        if 'mailto:' in page_text or 'mail()' in page_text:
            return -1
        return 1
    except:
        return 1

def Abnormal_URL(url, domain):
    try:
        w = get_whois(domain)
        if w and w.domain_name:
            registered = w.domain_name
            if isinstance(registered, list):
                registered = registered[0]
            if registered.lower() in domain.lower():
                return 1
        return -1
    except:
        return -1

# ─── HTML & JAVASCRIPT FEATURES ─────────────────────────

def Redirect(response):
    try:
        redirects = len(response.history)
        if redirects <= 1:
            return 1
        elif redirects <= 3:
            return 0
        else:
            return -1
    except:
        return 1

def on_mouseover(soup):
    try:
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string and 'onmouseover' in script.string.lower():
                return -1
        return 1
    except:
        return 1

def RightClick(soup):
    try:
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string and 'event.button==2' in script.string:
                return -1
        return 1
    except:
        return 1

def popUpWidnow(soup):
    try:
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string and 'window.open' in script.string:
                return -1
        return 1
    except:
        return 1

def Iframe(soup):
    try:
        iframes = soup.find_all('iframe')
        for iframe in iframes:
            if iframe.get('frameborder') == '0':
                return -1
        return 1 if not iframes else 0
    except:
        return 1

# ─── DOMAIN FEATURES ────────────────────────────────────

def age_of_domain(url):
    try:
        domain = get_domain(url)
        w = get_whois(domain)
        if w and w.creation_date:
            created = w.creation_date
            if isinstance(created, list):
                created = created[0]
            age_months = (datetime.now() - created).days / 30
            return 1 if age_months >= 6 else -1
    except:
        pass
    return -1

def DNSRecord(url):
    try:
        domain = get_domain(url)
        dns.resolver.resolve(domain, 'A')
        return 1
    except:
        return -1

def web_traffic(url):
    # Without Alexa API we approximate using a simple check
    # Returns suspicious (0) by default — can be improved later
    try:
        domain = get_domain(url)
        socket.gethostbyname(domain)
        return 0
    except:
        return -1

def Page_Rank(url):
    # PageRank API is deprecated — we return suspicious by default
    return 0

def Google_Index(url):
    try:
        query = f"site:{url}"
        response = requests.get(
            f"https://www.google.com/search?q={query}",
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=10
        )
        return 1 if "did not match any documents" not in response.text else -1
    except:
        return 1

def Links_pointing_to_page(url, soup):
    try:
        links = soup.find_all('a', href=True)
        count = len(links)
        if count == 0:
            return -1
        elif count <= 2:
            return 0
        else:
            return 1
    except:
        return -1

def Statistical_report(url, domain):
    # Known phishing domains/IPs from PhishTank top lists
    phish_domains = [
        '000free.us', 'lookout.com.de', 'paypal.com.security-check.tk'
    ]
    return -1 if domain in phish_domains else 1

# ─── MAIN EXTRACTOR ─────────────────────────────────────

def extract_features(url):
    domain = get_domain(url)
    response = fetch_page(url)
    soup = None

    if response:
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
        except:
            soup = BeautifulSoup('', 'html.parser')
    else:
        soup = BeautifulSoup('', 'html.parser')

    features = {
        'having_IP_Address':          having_IP_Address(url),
        'URL_Length':                  URL_Length(url),
        'Shortining_Service':          Shortining_Service(url),
        'having_At_Symbol':            having_At_Symbol(url),
        'double_slash_redirecting':    double_slash_redirecting(url),
        'Prefix_Suffix':               Prefix_Suffix(url),
        'having_Sub_Domain':           having_Sub_Domain(url),
        'SSLfinal_State':              SSLfinal_State(url, response),
        'Domain_registeration_length': Domain_registeration_length(url),
        'Favicon':                     Favicon(url, soup, domain),
        'port':                        port(url),
        'HTTPS_token':                 HTTPS_token(url),
        'Request_URL':                 Request_URL(url, soup, domain),
        'URL_of_Anchor':               URL_of_Anchor(url, soup, domain),
        'Links_in_tags':               Links_in_tags(url, soup, domain),
        'SFH':                         SFH(url, soup, domain),
        'Submitting_to_email':         Submitting_to_email(url, soup),
        'Abnormal_URL':                Abnormal_URL(url, domain),
        'Redirect':                    Redirect(response) if response else 1,
        'on_mouseover':                on_mouseover(soup),
        'RightClick':                  RightClick(soup),
        'popUpWidnow':                 popUpWidnow(soup),
        'Iframe':                      Iframe(soup),
        'age_of_domain':               age_of_domain(url),
        'DNSRecord':                   DNSRecord(url),
        'web_traffic':                 web_traffic(url),
        'Page_Rank':                   Page_Rank(url),
        'Google_Index':                Google_Index(url),
        'Links_pointing_to_page':      Links_pointing_to_page(url, soup),
        'Statistical_report':          Statistical_report(url, domain),
    }

    return features