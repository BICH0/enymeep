<div align="center">
  <img src="https://github.com/BICH0/enymeep/assets/81905574/8ce661c3-01c2-4409-a3dd-766c9baf1020" alt="Logo" height="80">  

  ### Enymeep  
  
  Port scanner made with python3, like Nmap but worse, like a lot worse  
  
  [**Explore the docs »**](https://github.com/BiCH0/enymeep)  
  [View Demo](https://github.com/BiCH0/enymeep/#Examples) · [Report Bug](https://github.com/BiCH0/enymeep/issues) · [Request Feature](https://github.com/BiCH0/enymeep/issues)
  
</div>

# Index
* ### [Requirements](#-requirements)
* ### [Installation](#-installation)
* ### [Usage](#-usage)
* ### [License](#-license)

# 💻 Requirements
To run this app you only need [python3](https://www.python.org/downloads/)
# 🚀 Installation
To install enymeep follow these steps:
1. Clone the repository and set it as your working directory   
   ```
   git clone https://github.com/BICH0/enymeep
   cd enymeep
   ```
2. (Optional) Create a venv  
   ```python -m venv .```
3. Install the required packages  
   ```pip install -r requirements.txt```
4. (Optional) Add enymeep to your path
   This step must be done from the enymeep folder  
   If you want to use it without calling it via python3 command you can follow these steps:
   * Option 1  
       Adding enymeep folder to $PATH  
         ```PATH=$PATH:$(pwd) && echo $PATH ```  
       Copy the output of the previus command and paste it at the end of your shell's config (.bashrc, .kshrc, .zshrc...)
   * Option 2 (Recommended)
       Create a symbolic link to enymeep  
       ```ln -S $(pwd)/enymeep.py /usr/bin/enymeep```
# ☕ Usage
```
Enyemeep [-h] -t IP -p PORTS [-v VERBOSITY] [-O] [-Pn] [--colorize] [-o [OUTPUT]] [-r]

Look for open ports

options:
  -h, --help                    Show this help message and exit

  -t IP, --target IP            Ip to scan, can be a range.

  -p PORTS, --port PORTS        Which port/s do you want to scan, if multiple, use commas port1,port2,port

  -v VERBOSITY, --verbose VERBOSITY
                        Verbosity level: 
                          0 (Default): Show only open ports
                          1: Show all ports even if they seem closed
                          2: Show all ports with full verbosity
                          3: Show debug messages

  -O, --os              Get OS from TTL

  -Pn, -8--D            Assume all targets are online

  --colorize            Get colorized output

  -o [FILE], --output [FILE]        Write a file with all the open/closed ports, verbosity level is used to write,
                                    default path is /tmp/enymeep-<date>.txt

  -r, --randomize                Randomize port scan order, this makes the scan more silent
                                 (like an elephant wearing yarn socks)

By BiCH0, with the WTFPL License
```
## Examples
### Scan all target ports and show only active ports
```
enymeep -t 192.168.1.10 -p-

Output-----

Scanning 192.168.1.10 for open ports -
--[ 192.168.1.10 ]------
   Status: Up
   Ports:
    - [22]: Open  
    - [23]: Open
```

### Store scan into file (default /tmp/enymeep-<date>.txt)
```
enymeep -t 192.168.1.10 -p22,77 -v1 -o

/tmp/enymeep-<date>.txt-----

Scanning 192.168.1.10 for open ports -
--[ 192.168.1.10 ]------
   Status: Up
   Ports:
    - [22]: Open  
    - [77]: Closed    - [78]: Closed
```
# 📜 License
```
        DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE 
                    Version 2, December 2004 

 Copyright (C) 2004 Sam Hocevar <sam@hocevar.net> 

 Everyone is permitted to copy and distribute verbatim or modified 
 copies of this license document, and changing it is allowed as long 
 as the name is changed. 

            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE 
   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION 

  0. You just DO WHAT THE FUCK YOU WANT TO.
```
<a href="http://www.wtfpl.net/"><img
       src="http://www.wtfpl.net/wp-content/uploads/2012/12/wtfpl-badge-4.png"
       width="80" height="15" alt="WTFPL" /></a>
