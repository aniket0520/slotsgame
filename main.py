from flask import Flask, request, jsonify
import requests
import re  # For regular expressions

app = Flask(__name__)

def send_request(url):
    try:
        response = requests.get(url)
        return response
    except requests.exceptions.RequestException as e:
        return str(e)

def analyze_response_headers(response):
    headers = response.headers
    server_header = headers.get('Server', "No Server header found")
    xpoweredby_header = headers.get('X-Powered-By', "No X-Powered-By header found")
    hsts_enabled = "HTTP Strict Transport Security (HSTS) is enabled" if 'Strict-Transport-Security' in headers else "HSTS is not enabled"

    # Advanced Techniques:
    x_frame_options = headers.get('X-Frame-Options', "No X-Frame-Options header found")
    x_xss_protection = headers.get('X-XSS-Protection', "No X-XSS-Protection header found")
    server_signature = re.search(r'[\(](.*?)[\)]', server_header)  # Extract server signature (if present)

    return {
        'Server': server_header,
        'X-Powered-By': xpoweredby_header,
        'HSTS': hsts_enabled,
        'X-Frame-Options': x_frame_options,
        'X-XSS-Protection': x_xss_protection,
        'Server Signature': server_signature.group(1) if server_signature else "None"  # Extract signature from regex match
    }

def analyze_response_code(response):
    status_code = response.status_code
    if status_code == 200:
        return "Server is likely Apache or IIS (common for success)"
    elif status_code == 403:
        return "Server is likely running a web application firewall (WAF)"
    elif status_code == 500:
        return "Server is likely running a vulnerable version of the web application"
    elif status_code == 301 or status_code == 302:
        return f"Server is performing a redirect to {response.headers.get('Location', 'Unknown location')}"
    else:
        return f"Unknown server response code: {status_code}"

def analyze_cookies(response):
    cookies = response.cookies
    if cookies:
        return [cookie.name for cookie in cookies]
    else:
        return []

def analyze_page_content(response):
    content_type = response.headers.get('Content-Type')
    if content_type and 'text/html' in content_type:
        page_content = response.text
        if 'WordPress' in page_content:
            return "Server is likely running WordPress"
        elif 'Drupal' in page_content:
            return "Server is likely running Drupal"
        else:
            return "Page content does not reveal server information"
    else:
        return "Page content is not HTML"

@app.route('/scan', methods=['GET'])
def scan():
    url = request.args.get('url')
    response = send_request(url)
    if isinstance(response, str):
        return jsonify({'error': response}), 500
    headers_result = analyze_response_headers(response)
    code_result = analyze_response_code(response)
    cookies_result = analyze_cookies(response)
    page_content_result = analyze_page_content(response)

    return jsonify({
        'Headers': headers_result,
        'Response Code': code_result,
        'Cookies': cookies_result,
        'Page Content': page_content_result
    })

if __name__ == '__main__':
    app.run(debug=True)
