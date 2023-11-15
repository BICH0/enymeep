import argparse
from ping3 import ping
from socket import socket
import re

# Realiza un programa en python que reciba parámetros que detecte máquinas encendidas y puertos abiertos, por ejemplo el 80, 21,22; empleando los módulos para hacer ping y socket. Ejemplos de parámetros pueden ser:
# -h ofrece ayuda y es opcional
# -t espera una dirección ip del target y es obligatoria
# - parámetro posicional con la ip o dirección de red
# -p puerto a testear, por defecto el 80
# -v n nivel de verbosidad
# --open muestre sólo los puertos abiertos
# o cualquiera que se te ocurra, pero el help debe dejar claro cómo usar el script
# El programa mostrará los argumentos pasados y controlará los errores si no se pasan argumentos o se pasan de forma incorrecta.
parser = argparse.ArgumentParser(
    prog='Enyemeep',
    description='Look for open ports',
    epilog='By BiCH0, with the WTFPL License',
    formatter_class=argparse.RawTextHelpFormatter
)
parser.add_argument(
    '-t',
    help='Ip to scan, can be a range.',
    dest="ip",
    required=True
    )
parser.add_argument(
    '-p',
    help='Which port/s do you want to scan, if multiple, use commas port1,port2,port',
    dest='ports',
    required=True
)
parser.add_argument(
    '-v',
    default=0,
    help='Verbosity level: \n  0 (Default): Show only open ports\n  1: Show all ports even if they seem closed\n  2: Show all ports with full verbosity',
    dest='verbosity',
    type=int
)
parser.add_argument(
    '-O',"--os",
    help='Get OS from TTL',
    action="store_true",
)

class stringItem:
    def __init__(self,content,verbosity=0):
        self.content = content
        self.verbosity = verbosity

def verbosityHandler(string,defVLvl=0):
    if string.verbosity <= defVLvl:
        if string.verbosity == 2:
            sting.content = "[DEBUG] " + string.content
        print(string.content)

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
        print(portRange)
        res=checkPortValidity(portRange)
        if len(res) == 0:
            nports = []
            for p in range(int(portRange[0]),int(portRange[1])+1,1):
                parsedArgs["ports"].append(p)
    else:
        ports = ports.split(",")
        res=checkPortValidity(ports)
    invalidPorts = res
    #ERROR HANDLING------------
    if len(invalidPorts) > 0:
        invalidPorts = ",".join(invalidPorts)
        exitMsg.append(f"Invalid port/s {invalidPorts}, port number/s must be between 1 and 65535")
    if len(exitMsg) != 0:
        for msg in exitMsg:
            print(f"[ERROR] {msg}")
        exit(1)
    return parsedArgs

def scanTarget(ip,ports,verbosity):
    # print("bim bim, bam bam, cyka")
    status="Down"
    rvalue=None
    if verbosity == 2:
        print(f"{ip}------")
        print("Testing conectivity...")
        for x in range(1,5,1):
            print(f"ping '{ip}' ... ", end="")
            res = ping(ip, timeout=2)
            if res is None:
                print("Timeout")
            else:
                if res is False:
                    print("Too far")
                    break
                else:
                    rvalue=True
                    print(res)
    else:
        rvalue=ping(ip, timeout=2)
    if rvalue is not None:
        print(f"{ip}------\n   Status: Up")
        # print(ports)
        c=0
        for port in ports:
            s = socket()
            try:
                socketRes = s.connect((ip,port))
                print(f" - [{port}]: Open")
            except KeyboardInterrupt:
                print("User finished process, exiting...")
                break
            except:
                if verbosity != 0:
                    endVal=""
                    if c >= 5:
                        c=0
                        endVal="\n"
                    c=c+1
                    print(f" - [{port}]: Closed",end=endVal)
    else:
        if verbosity != 0:
            print(f"{ip}------\n   Status: Down")


def main():
    args = parser.parse_args() #Recogemos los parametros {ip,port,verbosity}
    scanParams=argParser(args) #Devolvemos {ports:List,ip:{addr: String,net: Bool,cidr: Int}}
    verbosity = args.verbosity
    print('\n\nWelcome to Enymeep a python based nmap (but a lot worse, like, a lot)\n')
    print(scanParams)
    print(f'Scanning {args.ip} for open ports {args.ports}')
    ports=scanParams["ports"]
    ipAddr=scanParams["ip"]["addr"]
    try:
        if scanParams["ip"]["net"]:
            ipAddr=ipAddr[0:-2]
            for ip in range(1,254,1):
                scanTarget(f"{ipAddr}.{ip}",ports,verbosity)
        else:
            scanTarget(ipAddr,ports,verbosity)
    # if args.os:
    #     if ping(ipAddr, TTL=200) <= 64:
    #         print("OS: Linux")
    #     else:
    #         print("OS: Windows")
    #Request on port and watch headers
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print("An error ocurred: ")
        print(e)

main()