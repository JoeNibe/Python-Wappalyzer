import log
import json
import time
import re
import requests
from bs4 import BeautifulSoup
import pprint
import sys
import concurrent
import urllib3
urllib3.disable_warnings()
import threading
threadLock = threading.Lock()

from concurrent.futures import ThreadPoolExecutor
from selenium.webdriver.firefox.options import Options
from selenium import webdriver

# Importing color module
from colorama import Fore, init
init()

LOGGER = log.setup_logger(__name__, con_level=3)

# LOGGER.test("THis us a test")
# LOGGER.good("this is also a rest")
# LOGGER.error("oohn no its an erroe")
# LOGGER.warning("hehehi")
# LOGGER.run("this is run")
# LOGGER.critical("on fire")

# Globals
APPS_JSON = "./apps.json"
wappalyzer = None
driver = None
headers = {'User-Agent': r'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0'}


class WappalyzerError(Exception):
    """
    Raised for fatal Wappalyzer errors.
    """
    pass


class WebPage(object):
    """
    Simple representation of a web page, decoupled
    from any particular HTTP library's API.
    """

    def __init__(self, url, verify=False):
        """

        :param url: the url of the website to analyze
        :param verify: to enable or disable certificate verification
        """
        try:
            response, self.redirect = self._check_200(url, verify=verify)
            self.url = response.url
            self.html = response.text
            self.headers = response.headers
            self.headers.keys()
            self._parse_html()
        except AttributeError:
            raise ValueError("Headers must be a dictionary-like object")
        except Exception as e:
            LOGGER.error(f"Error getting URL {e}")

    def _parse_html(self):
        """
        Parse the HTML with BeautifulSoup to find <script> and <meta> tags.
        """
        self.parsed_html = soup = BeautifulSoup(self.html, 'html.parser')
        self.scripts = [str(script) for script in soup.findAll('script')]
        self.meta = {
            meta['name'].lower():
                meta['content'] for meta in soup.findAll(
                'meta', attrs=dict(name=True, content=True))
        }

    @staticmethod
    def _check_200(url, verify=False):
        redirect = False
        response = requests.get(url, headers=headers, verify=verify)
        LOGGER.debug("Response Code:" + str(response.status_code))

        # check if the domain was redirected to a diff domain
        if url.split('://')[-1] not in response.url[:len(url) + 10]:
            LOGGER.run("Url was redirected to a different domain. Using 302 response")
            response = requests.get(url, headers=headers, verify=verify, allow_redirects=False)
            redirect = True
        else:
            # checks redirect ans prints out the path
            if response.history:
                LOGGER.info("Request was redirected to same domain")
                for resp in response.history:
                    LOGGER.debug(str(resp.status_code) + " - " + resp.url)
                LOGGER.debug(str(response.status_code) + " - " + response.url)
            else:
                LOGGER.info("Request was not redirected")
        return response, redirect


class Wappalyzer(object):
    """
    Wappalyzer class used for analyzing websites
    """

    def __init__(self):
        """
        Initialize a new Wappalyzer instance.
        """
        try:
            with open(APPS_JSON, "r", encoding='utf-8') as f:
                data = f.read()
                data = json.loads(data)
            self.categories = data['categories']
            self.apps = data['apps']
        except Exception as e:
            LOGGER.error(e)


def make_list(value):
    """
    Used to convert any object into list for iterating
    :param value: any object
    :return: list of object
    """
    if not isinstance(value, list):
        return [value]
    else:
        return value


def js_browser(js, driver):
    """
    Executes javascript in a page
    :param js: js to execute
    :return: returns the result of js executed in the webpage
    """
    try:
        return str(driver.execute_script(f"return String({js})"))
    except Exception as e:
        LOGGER.debug(e)
        return ""


def regex_check(regex, content):
    """
    Evaluates the regex against the content and extracts the version and confidence
    :param regex: regex to evaluate
    :param content: content against which regex is evaluated
    :return: tuple - matched(True, False), version, confidence
    """
    try:
        search_regex, version_regex, confidence_regex, = prepare_pattern(regex)
        matches = re.findall(search_regex, content, re.IGNORECASE)
        if matches:
            version = confidence = ""
            if ":\\" in version_regex:
                version = matches[int(version_regex.split("version:\\")[-1]) - 1]
            elif version_regex:
                version = version_regex.split("version:")[-1]

            if confidence_regex:
                confidence = confidence_regex.split("confidence:")[-1]
            return True, version, confidence
        else:
            return False, False, False
    except Exception as e:
        LOGGER.error(e)
        return False, False, False


def rep_slashes(value):
    return value.replace('\\\\', '\\')


def prepare_pattern(regex):
    """
    Separates a regex into search, version and confidence regexes
    :param regex: the regex to split
    :return: search_regex, version_regex, confidence_regex
    """
    version_regex = ""
    confidence_regex = ""
    search_regex = regex
    if '\\;' in regex:
        for reg in regex.split('\\;'):
            if 'version:' in reg:
                version_regex = rep_slashes(reg)
            elif 'confidence:' in reg:
                confidence_regex = rep_slashes(reg)
            else:
                search_regex = rep_slashes(reg)
    try:
        re.compile(search_regex, re.I)
        return search_regex, version_regex, confidence_regex
    except re.error as e:
        LOGGER.warning(f"compiling regex: {regex} {e}")
        # regex that never matches:
        # http://stackoverflow.com/a/1845097/413622
        return r'(?!x)x', "", ""


def add_app(app, detected_apps, matches, version, confidence, regex=""):
    """
    Adds a matched app to our db
    :param app: the app being evaluated
    :param detected_apps: detected app
    :param matches: if matched or not
    :param version: version if matched
    :param confidence: confidence if matched
    :param regex: the regex that matched. Used for debugging
    :return: dict of detected apps
    """
    if matches:
        LOGGER.debug(f"{app}  matched {regex}")
        if not detected_apps.get(app):
            detected_apps[app] = {'version': ""}
        if not detected_apps[app].get('version'):
            if version:
                LOGGER.debug(version)
                detected_apps[app]['version'] = version
            if confidence:
                detected_apps[app]['confidence'] = confidence
        if wappalyzer.apps[app].get('implies'):
            implies = make_list(wappalyzer.apps[app].get('implies'))
            for implied_app in implies:
                detected_apps[implied_app] = {'version': ""}

    return detected_apps


def analyze(webpage, driver):
    """
    Analyzes the webpage for matching apps
    """
    detected_apps = dict()

    header_cookies = webpage.headers.get('Set-Cookie')
    for app, value in wappalyzer.apps.items():
        # checking the cookies
        if header_cookies:
            if value.get('cookies'):
                for name, regex in value['cookies'].items():
                    if name in header_cookies:
                        detected_apps = add_app(app,
                                                detected_apps,
                                                # unpacking the output of static method regex_check
                                                *regex_check(regex, header_cookies),
                                                regex=regex)

        # checking the headers
        if value.get('headers'):
            for name, regex in value['headers'].items():
                if name in webpage.headers:
                    detected_apps = add_app(app,
                                            detected_apps,
                                            # unpacking the output of static method regex_check
                                            *regex_check(regex, webpage.headers[name]),
                                            regex=regex)

        # checking meta tags
        if value.get('meta'):
            for name, regex in value['meta'].items():
                if name in webpage.meta:
                    detected_apps = add_app(app,
                                            detected_apps,
                                            # unpacking the output of static method regex_check
                                            *regex_check(regex, webpage.meta[name]),
                                            regex=regex)

        # checking the html body
        html_regex = value.get('html')
        if html_regex:
            html_regex = make_list(html_regex)
            for regex in html_regex:
                detected_apps = add_app(app,
                                        detected_apps,
                                        # unpacking the output of static method regex_check
                                        *regex_check(regex, webpage.html),
                                        regex=regex)

        # checking the script tags
        script_regex = value.get('script')
        if script_regex:
            script_regex = make_list(script_regex)
            for regex in script_regex:
                for script in webpage.scripts:
                    detected_apps = add_app(app,
                                            detected_apps,
                                            # unpacking the output of static method regex_check
                                            *regex_check(regex, script),
                                            regex=regex)
        # checking the url of the application
        if value.get('url'):
            detected_apps = add_app(app,
                                    detected_apps,
                                    # unpacking the output of static method regex_check
                                    *regex_check(webpage.url, value.get('url')),
                                    regex=value.get('url'))

    # skip js checks if the page is redirecting us
    if not webpage.redirect:
        LOGGER.debug("Starting js checks...")
        for app, value in wappalyzer.apps.items():
            if value.get('js'):
                for name, regex in value['js'].items():
                    js_value = js_browser(name, driver)
                    if js_value and js_value != "None" and js_value != "undefined":
                        LOGGER.debug(f"{name}  {regex}  {js_value}")
                        detected_apps = add_app(app,
                                                detected_apps,
                                                # unpacking the output of static method regex_check
                                                *regex_check(regex, js_value),
                                                regex=regex)
    LOGGER.good(pprint.pformat(detected_apps))
    if detected_apps.get('WordPress'):
        with threadLock:
            print(f"{webpage.url},Wordpress,{str(detected_apps.get('WordPress'))}\n")
            out.write(f"{webpage.url},Wordpress,{str(detected_apps.get('WordPress'))}\n")


def spider_site(url, depth=1):
    pass


def run(url):
    # global driver
    LOGGER.debug("Initializing Firefox driver...")
    try:
        opts = Options()
        opts.headless = True
        driver = webdriver.Firefox(options=opts)
    except Exception as e:
        LOGGER.error(e)
    LOGGER.debug("Driver initialized")
    webpage = WebPage(url)
    LOGGER.debug("Webapage info")
    LOGGER.debug(webpage.headers)
    LOGGER.debug(webpage.scripts)
    LOGGER.debug(webpage.meta)
    LOGGER.debug("Webapage info end")
    driver.get(url)
    analyze(webpage, driver)
    driver.close()


def initialize():
    global wappalyzer
    LOGGER.run("Initializing Wappalyzer...")
    wappalyzer = Wappalyzer()
    LOGGER.run("Wappalyzer initialized")


initialize()

filename = sys.argv[1]
file = open(filename, 'r')
err = open("error.txt", 'w')
out = open('out.csv', 'w')

def print_status(complete, total, text=""):
    n_bar = 50
    percent = (complete/total) * n_bar
    display_text = f"{Fore.LIGHTGREEN_EX}{complete} Completed {Fore.RED}{total-complete} Remaining" + text
    sys.stdout.write(f"\r{Fore.CYAN}[{Fore.LIGHTGREEN_EX}"
                     f"{'=' * int(percent) + Fore.LIGHTYELLOW_EX + '>' * int(1-(percent//100)):{n_bar + 5}s}"
                     f"{Fore.CYAN}]{Fore.WHITE}{int(percent/n_bar*100)}%  {display_text}{Fore.RESET}")


start = time.time()
with ThreadPoolExecutor(max_workers=5) as pool:
    try:
        futures_set = set()
        urls = [url.strip() for url in file.readlines()]
        for url in urls:
            futures_obj = pool.submit(run, url)
            futures_set.add(futures_obj)

        while futures_set:
            # print(futures_set)
            # print(THREADS_COMPLETE)
            print_status(len(urls) - len(futures_set), len(urls),
                         text=f"  {Fore.LIGHTGREEN_EX}{time.time() - start:{.2}f} Elapsed")
            done, futures_set = concurrent.futures.wait(futures_set, return_when=concurrent.futures.FIRST_COMPLETED)
        print_status(len(urls) - len(futures_set), len(urls),
                     text=f"  {Fore.LIGHTGREEN_EX}{time.time() - start:{.2}f} Elapsed")
    except Exception as e:
        print(e)
err.close()
out.close()
LOGGER.good(f"\nTotal time elapsed {time.time() - start}:{0:.2f}")

# TODO spidering site in single depth for better result
# TODO Threading *
# TODO check if site is 200 or 302
