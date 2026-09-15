# DIALER CODE FUZZER AND BRUTEFORCER
#
# Fuzzing dialer codes to search for hidden menus
#
# @author: SDO
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
