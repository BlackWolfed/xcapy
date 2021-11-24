# import module
import sys
import requests
from pprint import pprint
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin

# Check if we are running this on windows platform
from requests.exceptions import MissingSchema

is_windows = sys.platform.startswith('win')
# Console Colors
if is_windows:
    # Windows deserves coloring too :D
    G = '\033[92m'  # green
    Y = '\033[93m'  # yellow
    B = '\033[94m'  # blue
    R = '\033[91m'  # red
    W = '\033[0m'  # white
    try:
        import win_unicode_console, colorama

        win_unicode_console.enable()
        colorama.init()
        # Now the unicode will work ^_^
    except:
        print("[!] Error: Coloring libraries not installed, no coloring will be used [Check the readme]")
        G = Y = B = R = W = G = Y = B = R = W = ''


else:
    G = '\033[92m'  # green
    Y = '\033[93m'  # yellow
    B = '\033[94m'  # blue
    R = '\033[91m'  # red
    W = '\033[0m'  # white


def no_color():
    global G, Y, B, R, W
    G = Y = B = R = W = ''


def banner():
    print("""%s
db    db  .o88b.  .d8b.  d8888b. db    db 
`8b  d8' d8P  Y8 d8' `8b 88  `8D `8b  d8' 
 `8bd8'  8P      88ooo88 88oodD'  `8bd8'  
 .dPYb.  8b      88~~~88 88~~~      88    
.8P  Y8. Y8b  d8 88   88 88         88    
YP    YP  `Y88P' YP   YP 88         YP     
    %s%s
# xcapy is a tool for scan xss in every form on your target
# Coded by : Mostafa Tamam
      
    """ % (G, W, Y))


banner()


# Curl Html form content from Urls

def get_all_forms(url):
    try:
        soup = bs(requests.get(url).content, "html.parser")
    except MissingSchema:
        print('%s[*] Please make sure to put your right schema [ex: https://example.com]' % Y)
    except:
        raise UnboundLocalError("%sPlease make sure to put your right schema [ex: https://example.com]" % R)
    return soup.find_all("form")


# Extracts all possible useful information about an HTML `form`

def get_form_details(form):
    details = {}
    # get the form action (target url)
    action = form.attrs.get("action")
    # get the form method (POST, GET, etc.)
    method = form.attrs.get("method", "get").lower()
    # get all the input details such as type and name
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    # put everything to the resulting dictionary
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details


# submit form

def submit_form(form_details, url, value):
    # construct the full URL (if the url provided in action is relative)
    target_url = urljoin(url, form_details["action"])
    # get the inputs
    inputs = form_details["inputs"]
    data = {}
    for input in inputs:
        # replace all text and search values with `value`
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
        input_name = input.get("name")
        input_value = input.get("value")
        if input_name and input_value:
            # if input name and value are not None,
            # then add them to the data of form submission
            data[input_name] = input_value

    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        # GET request
        return requests.get(target_url, params=data)


def scan_xss(url):
    # get all the forms from the URL
    forms = get_all_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}")
    js_script = "<Script>alert('hi')</scripT>"
    # returning value
    is_vulnerable = "%s[-] No xss found !!" % R
    # iterate over all forms
    for form in forms:
        form_details = get_form_details(form)
        content = submit_form(form_details, url, js_script).content.decode()
        if js_script in content:
            print(f"[+] XSS Detected on {url}")
            print("%s[*] Form details:" % R)
            pprint(form_details)
            is_vulnerable = True
            # won't break because we want to print available vulnerable forms
    return is_vulnerable


if __name__ == "__main__":
    url = input("%s[*] Enter your target [ex: https://example.com] : " % G)
    print("[*] Scan begin for {}".format(url))
    print(scan_xss(url))
    print("%s[*] Scan complete !!" % B)
