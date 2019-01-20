# git-It
This script lists subdomains of the domains/IPs provided in the input file and identifies public /.git and other directories/files for each domain/IP and its corresponding subdoamins.
# Setup
1. Install necessary modules
```
> pip3 install -r requirements.txt
```
2. Paste your virustotal api key in gitIt.py on line 43
# Usage
```
> python3 gitIt.py [INPUTFILE]
```
## Remarks
* The input file should contain one target per line.
* The script creates an output file named output_tester.txt that contains the list of domains and subdomains identified.
* The script identifies domain name of the IP Address (if an IP address is provided in the list of targets).
* Currently only virustotal is being used for subdomain enumeration.
## Acknowledgments
Inspired from:
* **newcon** - [newcon/SecurityTools](https://github.com/newcon/SecurityTools/)
* **internetwach** - [internetwache/GitTools](https://github.com/internetwache/GitTools/)
* **guelfoweb** - [guelfoweb/knock](https://github.com/guelfoweb/knock/)
