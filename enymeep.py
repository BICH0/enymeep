#!/usr/bin/env python3
import argparse
from ping3 import ping
from socket import socket
import re
from datetime import datetime
from os import mknod
from random import shuffle
from io import TextIOWrapper

parser = argparse.ArgumentParser(
    prog='Enyemeep',
    description='Look for open ports',
    epilog='By BiCH0, with the WTFPL License',
    formatter_class=argparse.RawTextHelpFormatter
)
parser.add_argument(
    '-t','--target',
    help='Ip to scan, can be a whole subnet.',
    dest="ip",
    required=True
    )
parser.add_argument(
    '-p','--port',
    help='Which port/s do you want to scan, if multiple, use commas port1,port2,port or ranges 80-443',
    dest='ports',
    required=True
)
parser.add_argument(
    '-v','--verbose',
    default=0,
    help='Verbosity level: \n  0 (Default): Show only open ports\n  1: Show all ports even if they seem closed\n  2: Show all ports with full verbosity\n 3: Show debug messages',
    dest='verbosity',
    type=int
)
parser.add_argument(
    '-O',"--os",
    help='Get OS from TTL',
    action="store_true",
)
parser.add_argument(
    '-Pn',"-8--D",
    help='Assume all targets are online',
    action="store_true",
)
parser.add_argument(
    "--colorize",
    help='Get colorized output',
    action="store_true",
)
parser.add_argument(
    '-o',"--output",
    help='Write a file with all the open/closed ports, verbosity level is used to write, default path is /tmp/enymeep-<date>.txt',
    dest="file",
    nargs='?', 
    default='false'
)
parser.add_argument(
    '-r',"--randomize",
    help='Randomize port scan order, this makes the scan more silent (like an elephant wearing yarn socks)',
    action="store_true",
)

class bcolors:
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    PURPLE = '\033[95m'
    ENDC = '\033[0m'

class stringItem:
    def __init__(self,content,sverbosity=0):
        self.content = content
        self.verbosity = sverbosity

def verbosityHandler(string,color=False,end="\n"):
    if string.verbosity <= verbosity:
        if type(filename) == TextIOWrapper:
            filename.write(string.content+end)
        if string.verbosity == 3:
            string.content = bcolors.WARNING + "[DEBUG] " + bcolors.ENDC + string.content
        if colorize and color != False:
            string.content = color + string.content + bcolors.ENDC
        print(string.content, end=end)

def checkPortValidity(ports):
    invalidPorts=[]
    for port in ports: #Split ports if there are many
        invalid=False
        try:
            port=int(port)
        except:
            invalidPorts=["-> Bad range"]
            invalid=True
            break
        if (port < 1 or port > 65535) or invalid: #Checking if port value is valid 1<port<65535
            invalidPorts.append(str(port))
    return invalidPorts

def argParser(args):
    parsedArgs = {"ports":[],"ip":{"addr":"","net":False,"cidr":24}}
    exitMsg = []
    if not re.search("^[1-9][0-9]{0,2}\.([0-9]{1,3}\.){2}[0-9]{1,3}(\/[1-9][0-9]{1,2})?$", args.ip):#Checking ip format
        ip=args.ip
        if not re.search("^(.+\.)+.+$", args.ip):
            exitMsg.append("Invalid ip, ip must be CIDR format (x.x.x.x or x.x.x.x/x)")
    else:
        ip,*cidr = args.ip.split("/", 1) #Split ip into two variables
        if len(cidr) != 0: #Check if /x exits, if it does then store it
            parsedArgs["ip"]["cidr"]=int(cidr[0])
        if int(ip.split(".")[-1]) == 0: #Check if ip ends in .0 if then scanning all net
            parsedArgs["ip"]["net"]=True
    parsedArgs["ip"]["addr"]=ip
    #PORT CHECK----------------
    ports=args.ports
    if "-" in ports:
        portRange=ports.split("-")
        if portRange[0] == "":
            portRange[0]="1"
        if portRange[1] == "":
            portRange[1]="65535"
        res=checkPortValidity(portRange)
        if len(res) == 0:
            nports = []
            for p in range(int(portRange[0]),int(portRange[1])+1,1):
                parsedArgs["ports"].append(p)
    else:
        ports = ports.split(",")
        parsedArgs["ports"] = map(int,ports)
        res=checkPortValidity(ports)
    invalidPorts = res
    #FINAL TOUCHES-------------
    if args.randomize:
        shuffle(parsedArgs["ports"])
    #ERROR HANDLING------------
    if len(invalidPorts) > 0:
        invalidPorts = ",".join(invalidPorts)
        exitMsg.append(f"Invalid port/s {invalidPorts}, port number/s must be between 1 and 65535")
    if len(exitMsg) != 0:
        for msg in exitMsg:
            verbosityHandler(stringItem(msg,0),bcolors.FAIL)
        exit(1)
    return parsedArgs

def scanTarget(ip,ports,osprobe,pn):
    if testConnectivity(ip):
        verbosityHandler(stringItem(f"--[ {ip} ]------\n   Status: ",0),False,"")
        verbosityHandler(stringItem("Up",0),bcolors.OKGREEN)
    else:
        vb = 1
        if pn:
            vb=0
        verbosityHandler(stringItem(f"--[ {ip} ]------\n   Status: ",vb),False,"")
        verbosityHandler(stringItem("Down",vb),bcolors.FAIL)
        if not pn:
            verbosityHandler(stringItem("---------------------------",2))
            print("")
            return
    if osprobe:
            verbosityHandler(stringItem("   Os: ",0),False,"")
            verbosityHandler(stringItem("Disabled, TTL not available",0),bcolors.FAIL)
            # ttl = ping(ipAddr, ttl=255)
            # if ttl<= 32:
            #     print("OS: Windows 95/98")
            # elif ttl <= 64:
            #     print("OS: Linux")
            # elif ttl <= 128 :
            #     print("OS: Windows")
            # else:
            #     print("OS: Solaris")
    verbosityHandler(stringItem("   Ports:",0))
    scanPorts(ip,ports)
    verbosityHandler(stringItem("---------------------------",2))
    print("")

def testConnectivity(ip):
    status="Down"
    rvalue=None
    if verbosity == 2:
        verbosityHandler(stringItem("Testing conectivity...",3))
        for x in range(1,5,1):
            verbosityHandler(stringItem(f"    ping '{ip}' ... ",1),bcolors.PURPLE, end="")
            res = ping(ip, timeout=2)
            if res is None:
                verbosityHandler(stringItem("Timeout",1),bcolors.FAIL)
            else:
                if res is False:
                    verbosityHandler(stringItem("Too Far",1),bcolors.FAIL)
                    break
                else:
                    rvalue=True
                    verbosityHandler(stringItem(res,1))
        print("")
    else:
        rvalue=ping(ip, timeout=2)
    if rvalue is not None:
        return True
    else:
        return False
    
def scanPorts(ip,ports):
    c=1
    for port in ports:
        s = socket()
        s.settimeout(3)
        try:
            socketRes = s.connect((ip,port))
            if c != 1:
                print("")
                c=1
            if port <= 9:
                port=" "+str(port)
            verbosityHandler(stringItem(f"    - [{port}]: ",0),False,"")
            verbosityHandler(stringItem("Open  ",0),bcolors.OKGREEN)
            s.close()
        except KeyboardInterrupt:
            print("")
            verbosityHandler(stringItem("User finished process, exiting...",3),bcolors.FAIL)
            return
        except OSError as e:
            if e.errno == 111:
                if verbosity != 0:
                    endVal=""
                    if c >= 5:
                        c=0
                        endVal="\n"
                    c=c+1
                    verbosityHandler(stringItem(f"    - [{port}]: ",0),False,"")
                    verbosityHandler(stringItem("Closed",1),bcolors.FAIL,end=endVal)
            elif e.errno == 113:
                verbosityHandler(stringItem("    No route to host",1),bcolors.FAIL)
                return
            else:
                if type(e) == TimeoutError:
                    if (c > 1):
                        verbosityHandler(stringItem("",1))
                    verbosityHandler(stringItem(f"    - [{port}]: ",0),False,"")
                    verbosityHandler(stringItem("Open  ",0),bcolors.OKGREEN)
                else:
                    verbosityHandler(stringItem(f"\nAn error has ocurred while scanning port {port}: {e.value}:",0),bcolors.FAIL)
                    print(e) 
                c=1
        except Exception as e:
            verbosityHandler(stringItem(f"An exception has ocurred while scanning port {port}:",0),bcolors.FAIL)
            print(e)

def main():
    global verbosity 
    global colorize
    global filename
    filename="false"
    args = parser.parse_args() #Recogemos los parametros {ip,port,verbosity}
    colorize = args.colorize
    verbosity = int(args.verbosity)
    scanParams=argParser(args) #Devolvemos {ports:List,ip:{addr: String,net: Bool,cidr: Int}}
    print('\n\nWelcome to Enymeep a python based nmap (but a lot worse, like, a lot)\n')
    verbosityHandler(stringItem("Verbosity level: 2",3))
    if args.file != 'false':
        filename=f"/tmp/enymeep-{datetime.today().strftime('%Y%m%d_%H%M%S')}.txt"
        if args.file is not None:
            filename=args.file
        verbosityHandler(stringItem(f"Using {filename} as output file",3))
        try:
            filename = open(filename, "w")
        except:
            verbosityHandler(stringItem("An error has ocurred during log creation: ",0),bcolors.FAIL)
            print(e)
    verbosityHandler(stringItem(f"Arguments: {args}\n",3))
    verbosityHandler(stringItem("Бим Бим Бам Бам Блять ",4))
    verbosityHandler(stringItem(f'Scanning {args.ip} for open ports {args.ports}',0))
    ports=scanParams["ports"]
    ipAddr=scanParams["ip"]["addr"]
    try:
        if scanParams["ip"]["net"]:
            ipAddr=ipAddr[0:-2]
            for ip in range(1,254,1):
                scanTarget(f"{ipAddr}.{ip}",ports,args.os,args.Pn)
        else:
            scanTarget(ipAddr,ports,args.os,args.Pn)
        filename.close()
    except KeyboardInterrupt:
        verbosityHandler(stringItem("User finished process, exiting...",3),bcolors.FAIL)
        pass
    except AttributeError as e:
        if str(e)[-6:-1] != "close":
            raise e
    except Exception as e:
        verbosityHandler(stringItem("An error has ocurred during execution: ",0),bcolors.FAIL)
        print(e)

main()
