import re
from chardet.universaldetector import UniversalDetector


# Search for ips
def check_for_ips(string):

    ip = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

    match = ip.findall(string)

    if match:
        print(match)
        #print("IP address found: {0} at position {1}".format(match.group(), match.span()))



def check_encoding(string):
    detector = UniversalDetector()
    detector.reset()
    try:
        detector.feed(string)
        detector.close()
        return detector.result()
    except TypeError: # string not encoded throws an exception
        return False
