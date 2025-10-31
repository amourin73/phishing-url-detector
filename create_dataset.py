import csv
import random


def create_phishing_urls():
    """Generate realistic phishing URLs"""
    phishing_urls = []

    # Random character domains (highly suspicious)
    random_domains = [
        "hujklwefq.com", "yugdshljfk.com", "qwernasdf.com", "zxcvbpoiu.com",
        "mnbvcxzlkj.com", "asdfghqwer.com", "poiuytrewq.com", "lkjhgfdsa.com",
        "qmwkdpsnf.com", "rtpgbzxcvm.com", "wlskdjhfn.com", "zpwoeirut.com",
        "abcdefghij.com", "klmnopqrst.com", "uvwxyzabcd.com", "efghijklmn.com"
    ]

    # IP address domains
    ip_domains = [
        "http://192.168.1.1/login", "http://10.0.0.1/admin", "http://172.16.254.1/verify",
        "http://185.62.58.45/webscr", "http://203.0.113.1/account", "http://198.51.100.1/auth"
    ]

    # Suspicious TLDs
    suspicious_tlds = [
        "secure-login.xyz", "verify-account.tk", "bank-update.ga", "payment-confirm.ml",
        "account-security.cf", "login-portal.top", "auth-service.gq", "wallet-verify.xyz",
        "crypto-update.club", "password-reset.work"
    ]

    # Brand impersonation
    brand_phishing = [
        "facebook-secure-login.com", "google-verify-account.net", "microsoft-online-service.org",
        "apple-id-confirm.com", "paypal-security-update.com", "amazon-account-verify.net",
        "netflix-billing-info.com", "instagram-auth-portal.com", "twitter-password-reset.net",
        "whatsapp-verification.com"
    ]

    # Short URL services (often used in phishing)
    short_urls = [
        "bit.ly/2m8tgdK", "tinyurl.com/suspicious123", "goo.gl/fakelink456",
        "t.co/malicious789", "is.gd/phishing000", "ow.ly/fake111",
        "buff.ly/susp222", "shorte.st/fake333"
    ]

    # Combine all phishing URLs
    phishing_urls.extend([f"http://{domain}" for domain in random_domains])
    phishing_urls.extend(ip_domains)
    phishing_urls.extend([f"http://{domain}" for domain in suspicious_tlds])
    phishing_urls.extend([f"https://{domain}" for domain in brand_phishing])
    phishing_urls.extend([f"http://{url}" for url in short_urls])

    return phishing_urls


def create_legitimate_urls():
    """Generate legitimate URLs"""
    legitimate_urls = [
        "https://www.google.com", "https://www.youtube.com", "https://www.facebook.com",
        "https://www.amazon.com", "https://www.github.com", "https://stackoverflow.com",
        "https://www.linkedin.com", "https://www.instagram.com", "https://www.twitter.com",
        "https://www.reddit.com", "https://www.microsoft.com", "https://www.apple.com",
        "https://www.netflix.com", "https://www.wikipedia.org", "https://www.spotify.com",
        "https://www.coursera.org", "https://www.khanacademy.org", "https://www.edx.org",
        "https://www.udemy.com", "https://www.bbc.com", "https://www.cnn.com",
        "https://www.nytimes.com", "https://www.nasa.gov", "https://www.whitehouse.gov"
    ]

    return legitimate_urls


def create_dataset():
    """Create balanced dataset of phishing and legitimate URLs"""
    phishing_urls = create_phishing_urls()
    legitimate_urls = create_legitimate_urls()

    # Create dataset
    dataset = []
    for url in phishing_urls:
        dataset.append({'url': url, 'label': 1})

    for url in legitimate_urls:
        dataset.append({'url': url, 'label': 0})

    # Shuffle the dataset
    random.shuffle(dataset)

    # Save to CSV
    with open('phishing_dataset.csv', 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['url', 'label']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for row in dataset:
            writer.writerow(row)

    print(f"✅ Dataset created with {len(dataset)} URLs")
    print(f"📊 Phishing URLs: {len(phishing_urls)}")
    print(f"📊 Legitimate URLs: {len(legitimate_urls)}")

    return dataset


if __name__ == "__main__":
    create_dataset()