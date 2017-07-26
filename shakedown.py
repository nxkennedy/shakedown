import os
from collections import Counter
import sys
import glob
import magic # lol
import operator
import time
import checks # ours
import codecs


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


# for our output
def bar():
    print("="*60)


#@TODO this is busted. Need to fix encoding check and make it so that the line number prints with all of the check findings. Also need to add way for findings to be quantified
def integrity_check(doc):
    with open(doc) as f:
        for line_number, line in enumerate(f, 1):
            try:
                encoding = checks.check_encoding(line)

                if encoding:
                    print("[!] {0}: Line Encoded in {1}".format(doc, encoding['encoding']))
                    continue

                checks.check_for_ips(line)

            except Exception as e:
                print("EXCEPTION: " + str(e))
                continue



def analyzer(files):
    ftypes = []
    dangerous_ftypes = []

    if len(files) < 2:
        print("\n[+] INITIAL STATS FOR '{0}'".format(files[0]))
        bar()

    # initial process
    for f in files:

        ftype = magic.from_file(f) # find out what type of file we're dealing with
        ftypes.append(ftype)
        #files.append([item, breed])

        if "exe" in ftype.lower():
            dangerous_ftypes.append([f, ftype])


    ftypes_stats = sorted(Counter(ftypes).items(), key=operator.itemgetter(1), reverse=True) # dict of file types sorted by count in descending order
    print("-> Filetypes Discovered: {0}\n".format(len(ftypes_stats)))
    print(" {:<45} {:<12} ".format('Type:','Count:'))
    print(" {:<45} {:<12} ".format('-----','------'))
    for t, c in ftypes_stats:
        if len(t) > 40:
            t = t[:40] + "..."
        print("* {:<45} {:<12}".format(t, c))
    time.sleep(1)

    if len(dangerous_ftypes) > 0:
        sys.stdout.write(YELLOW)
        print("\n[!] POTENTIALLY DANGEROUS FILE TYPES DETECTED ")
        bar()
        for evil in dangerous_ftypes:
            print("-> {0}\n* {1}\n".format(evil[0], evil[1]))
        sys.stdout.write(RESET)
        time.sleep(1)

    # secondary process
    print("\n[+] IN-DEPTH FILE INTEGRITY TESTING ")
    bar()
    risk = ["[ PASS ]", "[ FAIL ]", "[ UNK ]"]
    print(" {:<45} {:<12} ".format('File:','Result:'))
    print(" {:<45} {:<12} ".format('-----','-------'))
    for f in files:

        if "/" in f:
            print("-> Analyzing {0}...".format(f.split("/")[-1]), end="\r")
        elif "\\" in f:
            print("-> Analyzing {0}...".format(f.split("\\")[-1]), end="\r")
        else:
            print("-> Analyzing {0}...".format(f), end="\r")

        integrity_check(f)
        time.sleep(0.5)

        sys.stdout.write(GREEN)
        if "/" in f:
            print("-> {:<43} {:<12}".format(f.split("/")[-1], risk[0]))
        elif "\\" in f:
            print("-> {:<43} {:<12}".format(f.split("\\")[-1], risk[0]))
        else:
            print("-> Analyzing {0}...".format(f), end="\r")
            print("-> {:<43} {:<12}".format(f, risk[0]))
        sys.stdout.write(RESET)


def process_dir(directory):
    fcount = 0
    files = []
    folder = glob.glob('{0}/**'.format(directory), recursive=True)
    for item in folder:

        if os.path.isfile(item): # if not a file, it's a subdirectory
            files.append(item)
            fcount += 1

    print("\n[+] DIRECTORY STATS FOR '{0}'".format(directory))
    bar()
    print("-> Subdirectories Found: {0}\n-> Files to Analyze: {1}".format((len(folder) - 1 - fcount), (fcount)))

    analyzer(files)


def get_target():

    try:

        if len(sys.argv) > 2:
            print("\n[!] ERROR: TOO MANY ARGS. PLEASE ENTER MULTIPLE FILES/DIRS AS A COMMA SEPARATED STRING\n")
        elif len(sys.argv) == 2:

            if "," in sys.argv[1]:
                targets = sys.argv[1].split(",")
            else:
                targets = [sys.argv[1]]

        else:
            print("\n[!] ERROR: MISSING MINIMUM REQUIREMENT OF ARGS\n")
            #print(USAGE)

        #print("Analyzing '{0}'...".format(target))
        #time.sleep(1)

        for target in targets:
            if os.path.isfile(target):
                analyzer(target) #straight to the analyzer
            elif os.path.isdir(target):
                process_dir(target)
            else:
                print('\n[!] ERROR: "{0}" not found')


    except IndexError as e:
        print("\n[!] ERROR: THE DIRECTORY SPECIFIED IS EMPTY\n")

    except Exception as e:
        print("\n[!] ERROR {0}\n".format(e))


if __name__ == "__main__":
    sys.stdout.write(CYAN)
    print(banner +"_"*60 + "\n")
    sys.stdout.write(RESET)
    get_target()
    char = "="
    print("\n\n"+char*27 + " DONE "+ char*27 +"\n")
