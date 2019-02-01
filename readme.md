# Whot

## Features

> 0. URL/IP port scan
> 1. Intl. phone number lookup
> 2. WHOIS lookup
> 3. Resolve a URL to IP
> 4. Geolocate from a URL

### 0. URL/IP port scan

Either type **port-scan <address>** then manually enter the port (range), or
type **port-scan <address>:port(range)**. Output is both the list of found
open ports and the common uses for them.

Example formats:

    port-scan google.com:80 - Scan port 80

    port-scan portquiz.net:1-100 - Scan ports 1 to 100

    port-scan example.com<ENTER>10 - Scan port 10

Example output:


    > $ port-scan google.com:1-500        
    [*] Scanning a port range over 1000 is substantially slower.
    Port information for google.com (172.217.25.142)
    Result:
    443 (Hypertext Transfer Protocol over TLS/SSL [TCP, SCTP, UDP]/Quick UDP Internet Connections [UDP])
    80 (Hypertext Transfer Protocol [TCP, SCTP, UDP]/Quick UDP Internet Connections [UDP])

### 1. Intl. phone number lookup

Enter a phone number to receive information such as the registered state,
carrier, etc.

### 2. WHOIS lookup

Enter an address to receive whois information about it, including: Emails,
registered owner, address, state, zipcode, country, and name servers.

Example format:

    whois google.com

Example output:

    > $ whois google.com
    [+] Whois for google.com, updated 2018-02-21 18:36:40
    [+] Created: 1997-09-15 04:00:00
    [+] Registrar: MarkMonitor, Inc.
    [+] Emails: whoisrequest@markmonitor.com, abusecomplaints@markmonitor.com
    [+] Org: Google LLC
    [+] State: CA
    [+] Country: US
    [+] Name Servers: ns3.google.com, ns1.google.com, ns2.google.com,     ns4.google.com

### 3. Resolve to IP

Example format:

    resolve google.com

Example output:

    > $ resolve google.com
    [+] google.com resolved to: 216.58.199.78

### 4. Geolocate from URL

Example format:

    geo portquiz.net

Example output:

    > $ geo portquiz.net
    [+] 5.196.70.86 is from FR and is in Hauts-de-France and is located in Gravelines

### 4. emailspam

This will spam a targeted email account with your email body and subject.

Example format:

    emailspam

Example output:

    > $ emailspam
    Please enter your email: yeet@gmail.com
    Please enter your password: yeetmas
    Please enter the subject of the email: d
    Please input your message: d
    Please enter the targets email:  yeet2@gmail.com
    Number Of Emails: 999

### 5. gmailbrute

This will brute a targeted gmail account (Must Be Gmail) using the dictionary
attack method, you must have a password list.

Example format:

    gmailbrute

Example output:

    > $ gmailbrute
    Target: yeet@gmail.com
    Password List: yeet.txt

### Contributors

[tira](https://github.com/tira)

# whot
