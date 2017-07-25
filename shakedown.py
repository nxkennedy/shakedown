import os
from collections import Counter
import sys
import glob
import magic # lol
import operator
import time


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

#@TODO what if a file is passed? Or a dir with only one file in it? Or no files?

def check_for_bad():
    pass

def scan_file(target):

    char = "="
    print("\n[+] FILE ANALYSIS ")
    print(char*60)
    risk = ["[ PASS ]", "[ FAIL ]", "[ UNK ]"]
    print(" {:<45} {:<12} ".format('File:','Result:'))
    print(" {:<45} {:<12} ".format('-----','-------'))
    for item in target:
        print("-> Analyzing {0}...".format(item[0].split("/")[-1]), end="\r")
        check_for_bad()
        time.sleep(0.5)
        sys.stdout.write(GREEN)
        print("-> {:<43} {:<12}".format(item[0].split("/")[-1], risk[0]))
        sys.stdout.write(RESET)
    pass


def scan_dir(target):
    fcount = 0
    files = []
    ftypes = []
    dangerous_ftypes = []
    repo = glob.glob('{0}/**'.format(target), recursive=True)

    for item in repo:
        if os.path.isfile(item): # if not a file, it's a subdirectory
            fcount += 1
            breed = magic.from_file(item) # find out what kind of file we're dealing with
            ftypes.append(breed)
            files.append([item, breed])

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
    time.sleep(1)


    if len(dangerous_ftypes) > 0:
        sys.stdout.write(YELLOW)
        print("\n\n[!] POTENTIALLY DANGEROUS FILE TYPES DETECTED ")
        print(char*60)
        for thing in dangerous_ftypes:
            print("-> {0}\n* {1}\n".format(thing[0], thing[1]))
        sys.stdout.write(RESET)
        time.sleep(1)

    scan_file(files)


def get_target():
    try:

        target = sys.argv[1]
        print("Analyzing '{0}'...".format(target))
        time.sleep(1)
        if os.path.isfile(target):
            scan_file([target])
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
    char = "="
    print("\n\n"+char*27 + " DONE "+ char*27 +"\n")
