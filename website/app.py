# flask starter
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import pickle
import numpy as np
import re
import requests as r
import json

config = {
    "DEBUG": True
}

app = Flask(__name__, template_folder='.')
app.config.from_mapping(config)
app.secret_key = 'super secret key'

model = pickle.load(open('../data/model.pkl', 'rb'))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/predict', methods=['POST', 'GET'])
def predict():
    if request.form.values() == []:
        flash("Please enter a URL.")
        return redirect(url_for('index'))

    form_url = [str(x) for x in request.form.values()]
    form_url = form_url[0]
    
    # validate that its a url using regex
    if (re.match(r'^(ftp|http|https):\/\/[^ "]+$', form_url)) == None:
        flash('Invalid URL, please enter a valid URL.')
        return redirect(url_for('index'))

    # check if url is in blacklist
    bool_blacklist = checkBlacklist(form_url)
    if bool_blacklist:
        return render_template('index.html', pred='This URL is on the PhishTank blacklist! Do not access it.', blacklist=bool_blacklist)

    # number of dots in form_url
    n_dots = form_url.count('.')
    # subdomain level
    subdomain_level = n_dots + 1
    # path level if no double slash
    if form_url.count('//') == 1:
        path_level = form_url.count('/') - 3
    else:
        path_level = form_url.count('/') - 2
    # url length
    url_length = len(form_url)
    # number of dashes
    n_dashes = form_url.count('-')
    # number of dashes in hostname, 
    # after first dot if www. is present
    # else part before first dot
    if form_url.count('www.') == 1:
        n_dashes_hostname = form_url.count('-', form_url.index('.')+1)
    else:
        n_dashes_hostname = form_url.count('-', 0, form_url.index('.'))    

    # number of @ symbols
    at_symbol = 1 if form_url.count('@') > 0 else 0
    # number of tilde symbols
    tilde_symbol = 1 if form_url.count('~') > 0 else 0
    # number of underscores
    n_underscores = form_url.count('_')
    # number of percent symbols
    n_percent_symbols = form_url.count('%')
    # number of query components
    # if ? exists in url, count number of &
    if form_url.count('?') >= 1:
        n_query_components = form_url.count('&')
    elif form_url.count('?') == 1:
        n_query_components = 1
    else:
        n_query_components = 0

    # number of ampersand symbols
    n_ampersand_symbols = form_url.count('&')
    # number of hash symbols
    n_hash_symbols = form_url.count('#')
    # number of numbers using regex
    n_numbers = len(re.findall(r'\d+', form_url))
    # https or not
    https = 1 if 'https' in form_url else 0
    # whether url is an ip address
    is_ip_address = 1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', form_url) else 0
    # domain in subdomain (part between www. and .com)
    domain_in_subdomain = 1 if (form_url.split('.')[-2]) else 0
    # domain in path (if . present after first tld or cctld) using regex
    domain_in_path = len(re.findall(r'[a-zA-Z0-9-]{1,}(\.{1}[a-zA-Z0-9-]{1,}){1,2}', form_url))
    if domain_in_path > 1:
        domain_in_path = 1
    else:
        domain_in_path = 0
    # hostname length
    hostname_length = len(form_url.split('.')[0])
    # path length 
    path_length = len(form_url.split('//')[1].split('/')) if '//' in form_url else len(form_url.split('/')[1:])
    # query length
    query_length = len(form_url.split('?')[1:]) if '?' in form_url else 0
    # double slash in path
    # if dot exists before //
    double_slash_in_path = 1 if '.' in form_url.split('//')[0] else 0

    # number of sensitive words in url
    sensitive_words = ['secure', 'account', 'webscr', 'login', 'ebayisapi', 'signin', 'banking', 'confirm']
    n_sensitive_words = 0
    for word in sensitive_words:
        if word in form_url[0]:
            n_sensitive_words += 1

    final_features = [n_dots, subdomain_level, path_level, url_length, n_dashes, n_dashes_hostname, at_symbol, tilde_symbol, n_underscores, n_percent_symbols, n_query_components, n_ampersand_symbols, n_hash_symbols, n_numbers, https, is_ip_address, domain_in_subdomain, domain_in_path, hostname_length, path_length, query_length, double_slash_in_path, n_sensitive_words]
    final_features = np.array(final_features).reshape(1, -1)
    prediction = model.predict_proba(final_features)
    prediction = round(prediction[0][1]*100, 2)

    if prediction >= 50:
        prediction_msg = 'This URL is likely to be phishing. It is not recommended to access it.'
    elif prediction >= 25:
        prediction_msg = 'This URL is suspicious. Be cautious.'
    else:
        prediction_msg = 'This URL is not likely to be phishing.'

    return render_template('index.html', pred='This URL is NOT on the blacklist and the probability of it being phishing is {}%.{}'.format(prediction, prediction_msg), blacklist=bool_blacklist)
    
def checkBlacklist(url):
    # check if url is in blacklist
    # need to format url so that it can be compared with phish tank urls
    # remove https://
    
    if '//' in url:
        url = url.split('//')[1]
    # remove www.
    if 'www.' in url:
        url = url.split('www.')[1]
    
    print(url)

    phishtank_url = 'http://data.phishtank.com/data/online-valid.json'
    try:
        # get json data from phishtank
        # data = r.get(phishtank_url)
        # data_json = data.json()

        # data downloaded for testing purposes
        # our ip address has been rate limited
        with open('blacklist.json', 'r') as f:
            data_json = json.load(f)

        print(data_json[0]['url'])
        phish_id = ''
        # if url is in blacklist, return phish_id
        for i in range(len(data_json)):
            if url in data_json[i]['url']:
                phish_id = data_json[i]['phish_detail_url']
                return phish_id
        return False
    except:
        print("Error occured.")
        return False

if __name__ == '__main__':
    app.run(debug=True)