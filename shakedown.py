import os
from collections import Counter
import sys
import glob
import magic # lol
import operator


RED = "\033[1;31m"
YELLOW = "\033[1;33m"
BLUE = "\033[1;34m"
CYAN = "\033[1;36m"
GREEN = "\033[0;32m"
RESET = "\033[0;0m"
BOLD = "\033[;1m"
REVERSE = "\033[;7m"

banner = """
   ______        __          __
  / __/ /  ___ _/ /_____ ___/ /__ _    _____
 _\ \/ _ \/ _ `/  '_/ -_) _  / _ \ |/|/ / _ \\
/___/_//_/\_,_/_/\_\\\\__/\_,_/\___/__,__/_//_/

            File Integrity Analyzer

Version: 0.0.1
Author: nxkennedy
"""


def scan_file(target):

    pass


def scan_dir(target):
    fcount = 0
    ftypes = []
    dangerous_ftypes = []
    repo = glob.glob('{0}/**'.format(target), recursive=True)

    for item in repo:
        if os.path.isfile(item): # if not a file, it's a subdirectory
            fcount += 1
            breed = magic.from_file(item)
            ftypes.append(breed) # find out what kind of file we're dealing with

            if "exe" in breed.lower():
                dangerous_ftypes.append([item, breed])

    ftypes_stats = Counter(ftypes) # dict of file types with occurence Counter
    counter = sorted(ftypes_stats.items(), key=operator.itemgetter(1), reverse=True) # dumb
    char = "="
    print("\n[+] INITIAL FINDINGS ".format(target.upper()))
    print(char*60)

    print("-> Subdirectories Found: {0}\n-> Files to Analyze: {1}".format((len(repo) - 1 - fcount), (fcount)))
    print("-> Filetypes Discovered: {0}\n".format(len(ftypes_stats)))
    print(" {:<45} {:<12} ".format('Type:','Count:'))
    print(" {:<45} {:<12} ".format('-----','------'))
    for t, c in counter:
        if len(t) > 40:
            t = t[:40] + "..."
        print("* {:<45} {:<12}".format(t, c))


    if len(dangerous_ftypes) > 0:
        sys.stdout.write(YELLOW)
        print("\n\n[!] POTENTIALLY DANGEROUS FILE TYPES DETECTED ")
        print(char*60)
        for thing in dangerous_ftypes:
            print("-> {0}\n* {1}\n".format(thing[0], thing[1]))
        sys.stdout.write(RESET)


    print("\n\n"+char*27 + " DONE "+ char*27 +"\n")

    pass


def get_target():
    try:

        target = sys.argv[1]
        print("Analyzing {0}...".format(target))
        if os.path.isfile(target):
            scan_file(target)
        elif os.path.isdir(target):
            scan_dir(target)
        else:
            print('\n[!] ERROR: "{0}" not found')
            exit(0)

    except Exception as e:
        print("\n[!] ERROR {0}\n".format(e))


if __name__ == "__main__":
    sys.stdout.write(CYAN)
    print(banner +"_"*60 + "\n")
    sys.stdout.write(RESET)
    get_target()
