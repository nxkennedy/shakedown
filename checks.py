import re
from chardet.universaldetector import UniversalDetector


# Search for ips
def check_for_ips(string):

    ip = re.compile('(([2][5][0-5]\.)|([2][0-4][0-9]\.)|([0-1]?[0-9]?[0-9]\.)){3}'
                +'(([2][5][0-5])|([2][0-4][0-9])|([0-1]?[0-9]?[0-9]))')

    match = ip.search(string)
    if match:
        return "IP address found: {0} at position {1}".format(match.group(), match.span())


def check_encoding(string):
    detector = UniversalDetector()
    detector.reset()
    try:
        detector.feed(string)
        detector.close()
        return detector.result()
    except TypeError: # string not encoded throws an exception
        return False
