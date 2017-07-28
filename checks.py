import re

# Search for ips
def check_for_ips(string):

    ip = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

    match = ip.findall(string)

    if match:
        return match
        #print("IP address found: {0} at position {1}".format(match.group(), match.span()))


# check for possible shellcode strings
def check_for_shellcode(string):

    chars = re.compile(r"[0%\\][xX][0-9a-fA-F]+")
    match = chars.search(string)

    if match:
        return match
