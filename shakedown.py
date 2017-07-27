import os
from collections import Counter
import sys
import glob
import magic # lol
import operator
import time
import checks # ours
import codecs




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

# colors to choose from
RED = "\033[1;31m"
YELLOW = "\033[1;33m"
BLUE = "\033[1;34m"
CYAN = "\033[1;36m"
GREEN = "\033[0;32m"
RESET = "\033[0;0m"
BOLD = "\033[;1m"
REVERSE = "\033[;7m"

def write_color(color, string, r=False):
    sys.stdout.write(color)
    if r:
        print(string, end="\r")
    else:
        print(string)
    sys.stdout.write(RESET)

#@TODO this is busted. Need to fix encoding check and make it so that the line number prints with all of the check findings. Also need to add way for findings to be quantified
def integrity_check(doc):
    write_color(CYAN, "ANALYZING {0}...".format(doc))
    print("---")

    try:
        with open(doc) as f:
            fail = 0 # start our fail counter


            ### shell code loop
            write_color(YELLOW, "{:<43} {:<12}".format("[*] Looking for shellcode...", "[ IN PROGRESS ]"), r=True)
            time.sleep(2)
            sc_flag = 0
            for line_number, line in enumerate(f, 1):

                shell_code = checks.check_for_shellcode(line)
                if shell_code:
                    if sc_flag < 1:
                        write_color(RED, "{:<46} {:<17}".format("[!] POSSIBLE SHELLCODE FOUND", "[ FAIL ]"), r=False)
                    write_color(BLUE, "-> LINE: {0}\n-> CONTENT: {1}".format(line_number, line))
                    sc_flag += 1
                    time.sleep(0.25)


            f.seek(0) # back to the top of the file
            #if sc_flag

            ### ip loop
            write_color(YELLOW, "{:<43} {:<12}".format("[*] Looking for IPs...", "[ IN PROGRESS ]"), r=True)
            time.sleep(2)
            ip_flag = 0
            for line_number, line in enumerate(f, 1):
                ip = checks.check_for_ips(line)
                if ip:

                    if ip_flag < 1:
                        write_color(RED, "{:<46} {:<17}".format("[!] POSSIBLE IP ADDRESS FOUND", "[ FAIL ]"), r=False)

                    write_color(BLUE, "-> LINE: {0}\n-> CONTENT: {1}".format(line_number, line))
                    ip_flag += 1
                    time.sleep(0.25)
                    """
                    number_of_ips = len(ip)
                    ip = (', ').join(ip) # makes it a string instead of array
                    if number_of_ips > 1:
                        write_color(RED, "\n[!] {0} IP ADDRESSES FOUND \n-> {1}\n-> FILE: {2}\n-> LINE: {3}\n-> CONTENT: {4}".format(number_of_ips, ip, doc, line_number, line))
                    else:
                        write_color(RED, "\n[!] IP ADDRESS FOUND \n-> {0}\n-> FILE: {1}\n-> LINE: {2}\n-> CONTENT: {3}".format(ip, doc, line_number, line))
                    """

            print("\n") # Gives us some room
    except Exception as e:
        print("EXCEPTION: " + str(e))


        """
        ### bad libs loop
        for line_number, line in enumerate(f, 1):
            try:
                ip = checks.check_for_ips(line)
                if ip:
                    number_of_ips = len(ip)
                    ip = (', ').join(ip) # makes it a string instead of array
                    if number_of_ips > 1:
                        write_color(RED, "\n[!] {0} IP ADDRESSES FOUND \n-> {1}\n-> FILE: {2}\n-> LINE: {3}\n-> CONTENT: {4}".format(number_of_ips, ip, doc, line_number, line))
                    else:
                        write_color(RED, "\n[!] IP ADDRESS FOUND \n-> {0}\n-> FILE: {1}\n-> LINE: {2}\n-> CONTENT: {3}".format(ip, doc, line_number, line))

            except Exception as e:
                print("EXCEPTION: " + str(e))
                continue
            """

def analyzer(files):
    ftypes = []
    dangerous_ftypes = []

    if len(files) < 2: # means it's a directory
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
        # in case we're dealing with lin/win

        """
        if "/" in f:
            print("-> Analyzing {0}...".format(f.split("/")[-1]), end="\r")
        elif "\\" in f:
            print("-> Analyzing {0}...".format(f.split("\\")[-1]), end="\r")
        else:
            print("-> Analyzing {0}...".format(f), end="\r")
        """
        # send the file to the grinder
        integrity_check(f)
        time.sleep(0.5)
        """
        # this means the check passed
        #@TODO should print a color based on status of checks above
        sys.stdout.write(GREEN)
        if "/" in f:
            print("-> {:<43} {:<12}".format(f.split("/")[-1], risk[0]))
        elif "\\" in f:
            print("-> {:<43} {:<12}".format(f.split("\\")[-1], risk[0]))
        else:
            print("-> Analyzing {0}...".format(f), end="\r")
            print("-> {:<43} {:<12}".format(f, risk[0]))
        sys.stdout.write(RESET)
        """

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
    write_color(CYAN, banner +"_"*60 + "\n")
    get_target()
    char = "="
    print("\n\n"+char*27 + " DONE "+ char*27 +"\n")
