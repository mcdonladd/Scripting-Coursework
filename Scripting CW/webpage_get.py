"""
    Script: webpage_get.py
    Desc: Fetches data from a webpage.
    Author: PL & RM
    Last modified: March 2021 (function annotations, pylint)
"""
import sys
import urllib.request


def wget(url: str) -> str:
    """Retrieve a webpage via its url, and return its contents"""
    # open url like a file, based on url instead of filename
    webpage = urllib.request.urlopen(url)  # ADD YOUR CODE TO OPEN URL HERE
    # get webpage contents
    page_contents = webpage.read()
    page_contents = page_contents.decode()
    webpage.close()
    return page_contents


def main():
    """test cases"""
    # set test url argument
    # un-comment one test case at a time
    sys.argv.append("https://www.napier.ac.uk/")
    # sys.argv.append("https://asecuritysite.com/email02.txt")
    # sys.argv.append("https://raw.githubusercontent.com/first20hours/google-10000-english/master/20k.txt")

    # Check args
    if len(sys.argv) != 2:
        print("[-] Usage: webpage_get URL")
        return

    # Get web page
    print("[*] wget()")
    print(wget(sys.argv[1]))


if __name__ == "__main__":
    main()
