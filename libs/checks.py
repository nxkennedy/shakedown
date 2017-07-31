#################################################################################################
# Name: Checks (part for Shakedown)
# Author: Nolan Kennedy (nxkennedy)
#
# Description: Script to analyze a directory or file for what may be malicious content. Writes
#              findings to csv to assist manual analysis.
#       Currently checks for:
#                   * IP Addresses
#                   * URLs
#                   * Shellcode
#                   * URL Encoding
#                   * HTML Encoding
#
# Use Case: Vetting newly downloaded scripts for network usage
#
# Usage: python shakedown.py <directory_or_file>
#
#################################################################################################


import re

# Search for ips
def check_for_ips(string):
    ip = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
    match = ip.search(string)

    if match:
        return match


# Search for URLs
def check_for_urls(string):
    url =  re.compile(r"""((?:[a-z][\w-]+:(?:/{1,3}|[a-z0-9%])|www\d{0,‌​3}[.]|[a-z0-9.\-]+[.‌​][a-z]{2,4}/)(?:[^\s‌​()<>]+|(([^\s()<‌​>]+|(([^\s()<>]+‌​)))*))+(?:&#‌​40;([^\s()<>]+|((‌​;[^\s()<>]+)))*&‌​#41;|[^\s`!()[&#‌​93;{};:'".,<>?«»“”‘’‌​]))""", re.DOTALL)
    match = url.search(string)

    if match:
        return match


# Search for possible shellcode
def check_for_encoding_shellcode(string):
    shellcode = re.compile(r"[0%\\][xX][0-9a-fA-F]+")
    match = shellcode.search(string)

    if match:
        return match


# Search for strings with URL encoding
def check_for_encoding_url(string):
    url = re.compile(r"%[0-9a-fA-F]")
    match = url.search(string)

    if match:
        return match


# Search for strings with HTML encoding
def check_for_encoding_html(string):
    html = re.compile(r"&#[xX][0-9a-fA-F]")
    match = html.search(string)

    if match:
        return match

"""
# all in one check for encoding
def check_for_encoding:
    encodings = {'url': re.compile(r"%[0-9a-fA-F]"),
    'html': re.compile(r"&#[xX][0-9a-fA-F]"),
    'shellcode': re.compile(r"[0%\\][xX][0-9a-fA-F]+")
    }
    for encoding in encodings:
        match = encodings[encoding].search(string)

        if match:
            return match
"""
