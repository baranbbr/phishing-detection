import requests as r
import json

def fetchBlacklist():
    # fetch blacklist from phishtank
    # save to file
    phishtank_url = 'http://data.phishtank.com/data/online-valid.json'
    data = r.get(phishtank_url)
    data_json = data.json()
    # save to file
    with open('blacklist.json', 'w') as f:
        f.write(json.dumps(data_json))

if __name__ == '__main__':
    fetchBlacklist()