#!/usr/bin/env python
# -*- coding: utf-8 -*-

# DIALER CODE FUZZER AND BRUTEFORCER
#
# Fuzzing dialer codes to search for hidden menus
#
# @author: sd0lv
#

# usage: fuzzer_dialer.py [-h] [-i INPUTFILE] -o OUTPUTFILE [-bf]
# optional arguments:
#   -h, --help            show this help message and exit
#   -i INPUTFILE, --inputfile INPUTFILE
#                         Dialer code list
#   -o OUTPUTFILE, --outputfile OUTPUTFILE
#                         File to save results
#   -bf, --bruteforce     Bruteforce mode, inputfile not needed
#   -r,  --random         Randomize "*#" digits in Bruteforce mode

##  Example: 
##  python fuzzer_dialer.py -i dialer.lst -o output.txt -bf  --> Dictionary Mode
##  python fuzzer_dialer.py -o output.txt -bf  --> Bruteforce Mode
##  python fuzzer_dialer.py -o output.txt -bf --random --> Bruteforce Mode, random *# digits


import os
import commands
import sys, getopt
import signal
import time
import os.path
import argparse
import random
from itertools import product


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def summaryTable(outputfile, var):
    print (bcolors.BOLD + bcolors.HEADER + "\n\n****************************************************************************" + bcolors.ENDC)
    print (bcolors.BOLD + bcolors.HEADER + "********************************* SUMMARY ************************************" + bcolors.ENDC)
    print (bcolors.BOLD + bcolors.HEADER + "***************************  DIALER CODES FOUND ******************************" + bcolors.ENDC)
    print (bcolors.BOLD + bcolors.HEADER + "******************************************************************************" + bcolors.ENDC)
    print (bcolors.BOLD + bcolors.OKGREEN + var + bcolors.ENDC + "\n")
   
    f1 = open(outputfile, "a")         

    f1.write("\n\n****************************************************************************")
    f1.write("\n********************************* SUMMARY ************************************")
    f1.write("\n***************************  DIALER CODES FOUND ******************************")
    f1.write("\n******************************************************************************\n")
    f1.write(var)

# Init Logcat
def startLogcat():
    date_var = commands.getoutput("adb -s "+ idDevice +" shell date \'+%m-%d\ %H:%M\'")
    date_var = str(date_var) + ":00.000"
    date_var = date_var.replace(" ", "\ ")   

    info_logcat = commands.getoutput("adb -s "+ idDevice +" logcat -t " + str(date_var) + "")

    f = open(os.path.dirname(os.path.abspath(__file__)) + "/" + ".logcat_output.txt","w+")    
    f.write(info_logcat)
    f.close()

# Search for Dialer code in .logcat_output.txt
def MatchDialerCode(dialer_code, outputfile): 
    dialer_code = dialer_code.replace("\\","")

    f1 = open(outputfile, "a")     
    values = ''        
        
    f1.write("\n****************************************************************************\n")        
    f1.write("Trying: " + dialer_code)    

    print ("\n****************************************************************************")
    print (bcolors.BOLD + "Trying: " + dialer_code + bcolors.ENDC)

    f = open(os.path.dirname(os.path.abspath(__file__)) + "/" + ".logcat_output.txt", "r")
    flag = False

    for line in f:
        if "activated = true" in line and dialer_code in line:
            print ("****************************************************************************")            
            print (line)   
            f1.write("\n****************************************************************************\n")
            f1.write(line + "\n")            
            flag = True
            
        if "android_secret_code" in line and "ParseService" in line and flag == True:
            print (line)
            print (bcolors.OKGREEN + "CORRECT DIALER CODE: " + dialer_code + bcolors.ENDC)
            f1.write(line + "\n")
            f1.write("CORRECT DIALER CODE: " + dialer_code + "\n")
            values = values + dialer_code
                        
    f1.close()
    return values

# Generate random numbers with specified (n) length
def random_with_N_digits(n):
    range_start = 10**(n-1)
    range_end = (10**n)-1

    number="%05d" % random.randint(range_start, range_end)
    return number

# Generate random (*#) digits
def random_digits():       

    alphabet = ['*', '#']
    tmp = ''
    keywords = [''.join(i) for i in product(alphabet, repeat = 4)]
    tmp = keywords 
    keywords = [''.join(i) for i in product(alphabet, repeat = 3)]
    tmp = tmp + keywords 
    keywords = [''.join(i) for i in product(alphabet, repeat = 2)]
    tmp = tmp + keywords 
    keywords = [''.join(i) for i in product(alphabet, repeat = 1)]
    tmp = tmp + keywords 
    keywords = [''.join(i) for i in product(alphabet, repeat = 0)]
        
    return tmp

def run_adb_commands(dialer_code):
    global idDevice
    dialer_code = dialer_code.replace("#", "\#")
    os.system('adb -s '+ idDevice +' shell am start -a android.intent.action.DIAL 2> /dev/null')
    os.system('adb -s '+ idDevice +' shell input text "'+ dialer_code +'" 2> /dev/null')
    #os.system('adb -s '+ idDevice +' shell pkill -f "com.samsung.android.dialer" 2> /dev/null')
    os.system('adb -s '+ idDevice +' shell input keyevent 4 2> /dev/null')    
    os.system('adb -s '+ idDevice +' shell input keyevent 3 2> /dev/null')     

def clean_device_screen():
    global idDevice
    os.system('adb -s '+ idDevice +' shell input keyevent 4 2> /dev/null')
    os.system('adb -s '+ idDevice +' shell input keyevent 3 2> /dev/null')
    os.system('adb -s '+ idDevice +' shell pkill -f "com.samsung.android.dialer" 2> /dev/null')  

# Capturing CTRL+C signal and showing Summary Table
def exit_gracefully(signum, frame):

    signal.signal(signal.SIGINT, original_sigint)
    global summaryVar
    global outputfile

    try:
        if raw_input("\n" + bcolors.BOLD + bcolors.FAIL + "Really quit? (y/n)> " + bcolors.ENDC).lower().startswith('y'):
            summaryTable(outputfile, summaryVar)
            os.system('rm .logcat_output.txt')
            sys.exit(1)

    except KeyboardInterrupt:      
        summaryTable(outputfile, summaryVar)
        os.system('rm .logcat_output.txt')
        sys.exit(1)

    # restore the exit gracefully handler here    
    signal.signal(signal.SIGINT, exit_gracefully)


######################################## __MAIN__ #########################################

if __name__ == "__main__":

    inputfile = ''
    outputfile = ''
    summaryVar = ''
    idDevice = commands.getoutput("adb devices | awk '/\t/' | cut -f1")

    parser = argparse.ArgumentParser(description='DIALER CODE FUZZER AND BRUTEFORCER')
    parser.add_argument('-i','--inputfile',help='Dialer code list', required=False)
    parser.add_argument('-o','--outputfile',help='File to save results', required=True)
    parser.add_argument('-bf','--bruteforce', help='Bruteforce mode, inputfile not needed',required=False, action='store_true')
    parser.add_argument('-r','--random', help='Randomize "*#" digits in Bruteforce mode' ,required=False, action='store_true')
    
    args = parser.parse_args()
  
    inputfile = args.inputfile
    outputfile = args.outputfile
    bruteforceFlag = args.bruteforce
    randomFlag = args.random

    original_sigint = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, exit_gracefully)
    
    # BruteForce mode selected     
    if bruteforceFlag:
        print ("\n" + bcolors.BOLD + bcolors.WARNING + "Bruteforce mode selected!" + bcolors.ENDC + "\n")    
        if randomFlag:
            print (bcolors.BOLD + bcolors.WARNING + "Random [*#] values" + bcolors.ENDC + "\n")
        else:
            print (bcolors.BOLD + bcolors.WARNING + "Static [*#] values" + bcolors.ENDC + "\n")  

        # Clean device screen
        clean_device_screen()

        # Bruteforce for *# values
        digit_list = random_digits()
      
        list=[]
        while True:  # Bruteforce with non-repeated random numbers
            length = random.randint(1,15)
            r = random_with_N_digits(length)
            if r not in list: 
                list.append(r)    
                              
                if randomFlag: # Dynamic *# values      
                    for i in digit_list:
                        for j in digit_list:  

                            tmp = i + r + j              

                            # Run adb commands
                            run_adb_commands(tmp) 

                            # Starting and saving logcat log
                            startLogcat()

                            # Check if dialer code is correct
                            value = MatchDialerCode(tmp.strip(), outputfile)

                            if value:
                                summaryVar = summaryVar + "\n" + value            

                else:   # Static *# values    
                    tmp = "*\#" + r + "\#"
                 
                    # Run adb commands
                    run_adb_commands(tmp) 
                 
                    # Starting and saving logcat log
                    startLogcat()
                 
                    # Check if dialer code is correct
                    value = MatchDialerCode(tmp.strip(), outputfile)
                    if value:
                        summaryVar = summaryVar + "\n" + value           

        summaryTable(outputfile, summaryVar)
        os.system('rm .logcat_output.txt')


    # Fuzzer mode selected
    else:                 
        print ("\n" + bcolors.BOLD + bcolors.WARNING + "Dictionary attack mode selected!" + bcolors.ENDC + "\n")    

        ## Read lines from dictionary
        with open(inputfile, 'r') as f:
            var = f.readlines()
        
        # Clean device screen
        clean_device_screen()

        for i in var:
            # Run adb commands
            run_adb_commands(str(i))                 

            # Starting and saving logcat log
            startLogcat()     

            # Check if dialer code is correct
            value = MatchDialerCode(i.strip(), outputfile)

            if value:
                summaryVar = summaryVar + "\n" + value


        summaryTable(outputfile, summaryVar)
        os.system('rm .logcat_output.txt')
