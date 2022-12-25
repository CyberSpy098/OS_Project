import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from pprint import pprint
#------------------------------------------------------------------------- SQL INJECTION CODE ---------------------------------------------------------------------
# initializing an HTTP session and setting browser user agent
s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"

# It extracts all the forms from the given `url`, it returns all forms from the HTML content
def get_all_forms(url):
    soup = bs(s.get(url).content, "html.parser")
    return soup.find_all("form")

# This function extract all the useful information from forms..
def get_form_details(form):
    details = {}
    # get the form action (target url)
    try:
        action = form.attrs.get("action").lower()
    except:
        action = None
    # get the form method (POST, GET, etc.)
    method = form.attrs.get("method", "get").lower()
    # get all the input details such as type and name
    inputs = []
    for input__Tag in form.find_all("input"):
        input_type = input__Tag.attrs.get("type", "text")
        input_name = input__Tag.attrs.get("name")
        input_value = input__Tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})
    # put everything to the resulting dictionary
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

#A simple boolean function that determines whether a page is SQL Injection vulnerable from its response
def is_vulnerable(response):
    errors = {
        # MySQL
        "you have an error in your sql syntax;",
        "warning: mysql",
        # SQL Server
        "unclosed quotation mark after the character string",
        # Oracle
        "quoted string not properly terminated",
    }
    for error in errors:
        # if you find one of these errors, return True
        if error in response.content.decode().lower():
            return True
    # no error detected
    return False

#A Function that searches for all forms in given URL and tries to place quote and double quote characters in input fields.
def scan_sql_injection(URL):
    # test on URL
    f = open('sql_payload.txt', 'r')
    payloads = f.read().splitlines()

    for i in payloads:
        # add quote/double quote character to the URL
        URL = f"{URL}{i}"
        print("[!] Trying", URL)

        # make the HTTP request
        res = s.get(URL)
        if is_vulnerable(res):
            # SQL Injection detected on the URL itself,
            # no need to preceed for extracting forms and submitting them
            print("[+] SQL Injection vulnerability detected, link:", URL)
            return

    # test on HTML forms
    forms = get_all_forms(URL)
    print(f"[+] Detected {len(forms)} forms on {URL}.")

    for form in forms:
        form_details = get_form_details(form)
        for i in payloads:
            # the data body we want to submit
            data = {}
            for input_tag in form_details["inputs"]:
                if input_tag["value"] or input_tag["type"] == "hidden":
                    # any input form that has some value or hidden,
                    # just use it in the form body
                    try:
                        data[input_tag["name"]] = input_tag["value"] + i
                    except:
                        pass
                elif input_tag["type"] != "submit":
                    # all others except submit, use some junk data with special character
                    data[input_tag["name"]] = f"test{i}"

            # join the url with the action (form request URL)
            URL = urljoin(URL, form_details["action"])
            if form_details["method"] == "post":
                res = s.post(URL, data=data)
            elif form_details["method"] == "get":
                res = s.get(URL, params=data)

            # test whether the resulting page is vulnerable
            if is_vulnerable(res):
                print("[+] SQL Injection vulnerability detected, link:", URL)
                print("[+] Form:")
                pprint(form_details)
                break

def manually_scan_sql_injection(URL):
    # test on URL
    input_string = input('Enter elements of a list separated by space ')
    print("\n")
    user_list = input_string.split()

    for i in user_list:
        # add quote/double quote character to the URL
        URL = f"{URL}{i}"
        print("[!] Trying", URL)

        # make the HTTP request
        res = s.get(URL)
        if is_vulnerable(res):
            # SQL Injection detected on the URL itself,
            # no need to preceed for extracting forms and submitting them
            print("[+] SQL Injection vulnerability detected, link:", URL)
            return

    # test on HTML forms
    forms = get_all_forms(URL)
    print(f"[+] Detected {len(forms)} forms on {URL}.")

    for form in forms:
        form_details = get_form_details(form)
        for i in user_list:
            # the data body we want to submit
            data = {}
            for input_tag in form_details["inputs"]:
                if input_tag["value"] or input_tag["type"] == "hidden":
                    # any input form that has some value or hidden,
                    # just use it in the form body
                    try:
                        data[input_tag["name"]] = input_tag["value"] + i
                    except:
                        pass
                elif input_tag["type"] != "submit":
                    # all others except submit, use some junk data with special character
                    data[input_tag["name"]] = f"test{i}"

            # join the url with the action (form request URL)
            URL = urljoin(URL, form_details["action"])
            if form_details["method"] == "post":
                res = s.post(URL, data=data)
            elif form_details["method"] == "get":
                res = s.get(URL, params=data)

            # test whether the resulting page is vulnerable
            if is_vulnerable(res):
                print("[+] SQL Injection vulnerability detected, link:", URL)
                print("[+] Form:")
                pprint(form_details)
                break

#----------------------------------------------------------------------------------------------------------------------------------------------------------------
                                                  # XSS Vulnerability Scanner Code
def submit_form(form_details, url, value):
    """
    Submits a form given in `form_details`
    Params:
        form_details (list): a dictionary that contain form information
        url (str): the original URL that contain that form
        value (str): this will be replaced to all text and search inputs
    Returns the HTTP Response after form submission
    """
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

    print(f"[+] Submitting malicious payload to {target_url}")
    print(f"[+] Data: {data}")
    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        # GET request
        return requests.get(target_url, params=data)


def scan_xss(url):
    """
    Given a `url`, it prints all XSS vulnerable forms and
    returns True if any is vulnerable, False otherwise
    """
    # get all the forms from the URL
    f = open('xss_payloads.txt',encoding="utf8")
    js_script = f.read().splitlines()

    forms = get_all_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    #js_script = "<Script>alert('hi')</scripT>"
    # returning value
    is_vulnerable = False
    # iterate over all forms
    for i in js_script:
        for form in forms:
            form_details = get_form_details(form)
            content = submit_form(form_details, url, i).content.decode()
            if i in content:
                print(f"[+] XSS Detected on {url}")
                print(f"[*] Form details:")
                print(form_details)
                is_vulnerable = True
            # won't break because we want to print available vulnerable forms
        return is_vulnerable

def manually_scan_xss(url):
    input_string = input('Enter elements of a list separated by space ')
    print("\n")
    user_list = input_string.split()

    forms = get_all_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    #js_script = "<Script>alert('hi')</scripT>"
    # returning value
    is_vulnerable = False
    # iterate over all forms
    for i in user_list:
        for form in forms:
            form_details = get_form_details(form)
            content = submit_form(form_details, url, i).content.decode()
            if i in content:
                print(f"[+] XSS Detected on {url}")
                print(f"[*] Form details:")
                print(form_details)
                is_vulnerable = True
            # won't break because we want to print available vulnerable forms
        return is_vulnerable


#------------------------------------------------------------------------------ Main Function -----------------------------------------------------------------

if __name__ == "__main__":
    print("-" * 80)
    print("\t\t\t\t\t\t\t  Website Vulnerability Scanner  ")
    choose = 0

    while 1:
        print("-" * 80)
        print("\t\t\t\t\t\t\t\t\t\tMENU\t\t\t\t")
        print("-" * 80)
        print("Which scan do you want to do?")
        print("Press 1 : For Automated SQLi Vulnerability Scan")
        print("Press 2 : For Automated XSS Vulnerability Scan")
        print("Press 3 : For Manually  SQLi Vulnerability Scan")
        print("Press 4 : For Manually  XSS  Vulnerability Scan")
        print("Press 5 : Exit")
        print("-" * 80)
        choose=eval(input("Enter your choice : \t\t"))

        if choose == 1:
            print("\nEnter URL on which you have to perform SQL Injection vulnerability Scan :     ")
            url = input()
            #url = "http://testphp.vulnweb.com/artists.php?artist=1%22"
            scan_sql_injection(url)

        elif choose == 2:
            print("\nEnter URL on which you have to perform XSS vulnerability :      ")
            url = input()
            #url = "https://xss-game.appspot.com/level1/frame"
            scan_xss(url)

        elif choose == 3:
            print("\nEnter URL on which you have to perform SQLi vulnerability :      ")
            url = input()
            manually_scan_sql_injection(url)

        elif choose == 4:
            print("\nEnter URL on which you have to perform XSS vulnerability :      ")
            url = input()
            manually_scan_xss(url)

        elif choose == 5:
            exit();
