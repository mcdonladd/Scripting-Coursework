"""
    Script: email_analysis.py
    Desc: extracts email addresses and IP numbers from a text file or webpage;
    for example, from a saved email header
    Author: Petra Leimich Nov 2018. Pylint etc Mar2021
    NOTE: wget() and txt_get() may return a byte object,
    but regex only works with strings.
    So the byte object needs to be decoded somewhere.
"""
from typing import List
import sys
import urllib.request
import re
import collections 
from webpage_get import wget # imports your own webpage_get module
# if you don't want to import your existing module, define wget here:

# def wget(url):
# ... ADD YOUR CODE HERE ...
# return page_contents


def txt_get(filename: str) -> str:
    """Suitable function doc string here"""
    # open file read-only, get file contents and close

    with open(filename, "r") as infile:
        file_contents = infile.read().decode('utf-8')
    return file_contents


def find_ipv4(text):
    """Suitable function doc string here
    input = some text
    output = list of ips """

    ips = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", text)
    validips = []
    # check for valid IPs
    # check each octet is in 0..255
    for i in ips:
        possibleip = i.split(".")
        valid = True

        for n in possibleip:
            if int(n) not in range(0,256):
                valid = False

        if valid:
            validips.append(i)


    return validips


def find_email(text: str) -> List[str]:
    """Suitable function doc string here
    input = some text
    output = some emails"""
    text_str = text.decode('utf-8', errors='ignore') 

    emails = re.findall(r"\b(?:TO|FROM)\s*([^\\\t\r\n]+[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.\w{2,4})", text_str)

    #emails = re.findall(r"(\bTO\b|\bFROM\b)[^\\\t\r\n]+[a-zA-Z0-9.]+@[a-zA-Z0-9.]+\.\w{2,4}", text_str)

    return emails


def main() -> None:
    """Test cases"""
    # url arguments for testing
    # un-comment one of the following 4 tests at a time
    # sys.argv.append("https://www.napier.ac.uk")
    #sys.argv.append("https://asecuritysite.com/email01.txt")
    # sys.argv.append("https://asecuritysite.com/email02.txt")
    sys.argv.append("evidence-packet-analysis.pcap")

    # Check args
    if len(sys.argv) != 2:
        print("[-] Usage: email_analysis URL/filename")
        return

    inlocation = sys.argv[1]

    try:
        print(f"[+] Analysing {sys.argv[1]}")

        text = "" # the content that we are going to search inside

        # call wget() or txt_get() as appropriate
        if inlocation.startswith("http"):
            text = wget(inlocation)
        else:
            text = txt_get(inlocation)




        print("")
        print("[+] IP addresses found: ")
        iplist = find_ipv4(text)
        for ip in iplist:
            print(ip)
        print("\n")


        print("[+] email addresses found: ")
        emaillist = find_email(text)

        # do some counting
        emailcounts = collections.Counter(emaillist)
        for k,v in emailcounts.items():
            print(k, v)
        print("\n")

        for em in emaillist:
            print(em)

    except FileNotFoundError as err1:
        print(f"{inlocation} not found")
    except Exception as err:
        # error trapping goes here
        # ideally use mor specific exceptions
        print(err)  # ... ADD YOUR CODE HERE ...


if __name__ == "__main__":
    main()
