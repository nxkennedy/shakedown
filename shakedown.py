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
Author: Nolan Kennedy (nxkennedy)
"""

#@TODO what if a file is passed? Or a dir with only one file in it? Or no files?


# for our output
def bar():
    print("="*60)

# colors to choose from
RED = "\033[1;31m"
RED_DIM = "\033[2;31m"
YELLOW = "\033[1;33m"
BLUE = "\033[1;34m"
CYAN = "\033[1;36m"
GREEN = "\033[1;32m"
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
    write_color(BOLD, "==> '{0}'".format(doc))
    print("-" * (len(doc)+6))
    try:
        with open(doc) as f:
            #### shell code loop
            write_color(YELLOW, "{:<46} {:<17}".format("[*] Shellcode Check", "[ IN PROGRESS ]"), r=True)
            time.sleep(0.5)
            sc_flag = 0
            for line_number, line in enumerate(f, 1):

                shell_code = checks.check_for_shellcode(line)
                if shell_code:

                    if sc_flag < 1:
                        write_color(RED, "{:<46} {:<17}".format("[-] Shellcode Check", "[ FAIL ]"), r=False)
                        write_color(RED, "{:<46} {:<17}".format("[!] POSSIBLE SHELLCODE FOUND", "[ SEE BELOW ]"), r=False)

                    print("-> LINE: {0}\n-> CONTENT: {1}".format(line_number, line))
                    sc_flag += 1

            if sc_flag == 0:
                write_color(GREEN, "{:<46} {:<17}".format("[\u2714] Shellcode Check", "[ PASS ]"), r=False)


            f.seek(0) # back to the top of the file because we're about to reiterate over every loop
            #### ip loop
            write_color(YELLOW, "{:<46} {:<17}".format("[*] IP Address Check", "[ IN PROGRESS ]"), r=True)
            time.sleep(0.5)
            ip_flag = 0
            for line_number, line in enumerate(f, 1):
                ip = checks.check_for_ips(line)
                if ip:

                    if ip_flag < 1:
                        write_color(RED, "{:<46} {:<17}".format("[-] IP Address Check", "[ FAIL ]"), r=False)
                        write_color(RED, "{:<46} {:<17}".format("[!] POSSIBLE IP ADDRESS FOUND", "[ SEE BELOW ]"), r=False)

                    print("-> LINE: {0}\n-> CONTENT: {1}".format(line_number, line))
                    ip_flag += 1

            if ip_flag == 0:
                write_color(GREEN, "{:<46} {:<17}".format("[\u2714] IP Address Check", "[ PASS ]"), r=False)

            print("\n") # Gives us some room

    except UnicodeDecodeError as e:
        write_color(YELLOW, "{:<46} {:<17}".format("[!] ERROR: UNABLE TO READ FILE", "[ ERROR ]"))
        write_color(YELLOW, "-> {0}\n\n".format(e))

    except Exception as e:
        print("EXCEPTION: " + str(e))
        pass


def analyzer(files):
    ftypes = []
    dangerous_ftypes = []

    if len(files) < 2: # it's a file
        print("\n[+] INITIAL STATS FOR '{0}'".format(files[0]))
        bar()

    # initial process
    for f in files:
        ftype = magic.from_file(f) # find out what type of file we're dealing with
        ftypes.append(ftype)

        if "exe" in ftype.lower():
            dangerous_ftypes.append([f, ftype])

    ftypes_stats = sorted(Counter(ftypes).items(), key=operator.itemgetter(1), reverse=True) # dict of file types sorted by count in descending order
    print("-> Filetypes Discovered: {0}\n".format(len(ftypes_stats)))
    print(" {:<45} {:<12} ".format('Type:','Count:'))
    print(" {:<45} {:<12} ".format('-----','------'))
    for t, c in ftypes_stats:

        if len(t) > 40:
            t = t[:40] + "..." # truncate output

        print("* {:<45} {:<12}".format(t, c))
    time.sleep(1)

    if len(dangerous_ftypes) > 0:
        sys.stdout.write(YELLOW)
        print("\n[!] POTENTIALLY DANGEROUS FILE TYPES DETECTED ")
        bar()
        for evil in dangerous_ftypes:
            print("-> {0}\n* {1}\n".format(evil[0], evil[1]))
        sys.stdout.write(RESET)
        time.sleep(0.25)

    # secondary process
    print("\n[+] IN-DEPTH FILE INTEGRITY TESTING ")
    bar()
    print(" {:<45} {:<12} ".format('Test:','Result:'))
    print(" {:<45} {:<12} ".format('-----','-------'))
    for f in files:
        # send the file to the grinder
        integrity_check(f)

# take our dir and extract the files from it
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

        for target in targets:

            if os.path.isfile(target):
                analyzer([target]) # straight to the analyzer as an array
            elif os.path.isdir(target):
                process_dir(target) # will be processed into an array
            else:
                print('\n[!] ERROR: "{0}" not found')

    except IndexError as e:
        print("\n[!] ERROR: THE DIRECTORY SPECIFIED IS EMPTY\n")

    except Exception as e:
        print("\n[!] ERROR {0}\n".format(e))


if __name__ == "__main__":
    write_color(CYAN, banner +"_"*60 + "\n")
    time.sleep(0.25)
    get_target()
    char = "="
    write_color(BOLD, "\n\n"+char*27 + " DONE "+ char*27 +"\n")
