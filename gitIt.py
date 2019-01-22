import sys, socket
import urllib, json
from urllib import request
from urllib.parse import urlparse

def do_parse(target):
        isIP = ''
        domain = target
        try:
                isIP = socket.inet_aton(domain)
                print(isIP)
        except Exception as e:
                print(e)
                isIP = ''
        if isIP != '':
                #Check for Reverse DNS to get domain
                try:                        
                        #print(target)
                        domain = domain.strip()
                        domain_s = socket.gethostbyaddr(domain)
                        print(domain_s[0])
                        domain = domain_s[0]
                        with open('output_tester.txt','a') as output_file:
                                output_file.write(domain)
                                output_file.write('\n')
                        #print('Domain printed')
                except Exception as e:
                        print(e)
                        print('No domain found for corresponding IP')
        if target.startswith("http") or target.startswith("ftp"):
                #Check for netloc of domain
                target = target.strip()
                domain_parse = urlparse(target)
                domain = domain_parse.netloc
                with open('output_tester.txt','a') as output_file:
                                output_file.write(domain)
                                output_file.write('\n')
        
        getSubDomains(domain)

def getSubDomains(domain):
        virusTotal_url = 'https://www.virustotal.com/vtapi/v2/domain/report'
        virusTotal_apiKey = '<Enter your virustotal api here>'
        
        requestParameters_raw = {'apikey':virusTotal_apiKey, 'domain':domain, 'proxies':None, 'timeout':None}      
        requestParameters_encoded = urllib.parse.urlencode(requestParameters_raw)
        
        try:
                #response = request.get(virusTotal_url + 'domain/report', params=requestParameters_raw, proxies=None, timeout=None)
                response = urllib.request.urlopen('%s?%s' % (virusTotal_url, requestParameters_encoded))
                
                
                response_dict = json.loads(response.read())
                subdomains_raw = response_dict['subdomains']

                #print('hello -> '+subdomains_raw)
                with open('output_tester.txt','a') as output:
                        for subdomain in subdomains_raw:
                                output.write(subdomain)
                                output.write('\n')
                                print(subdomain+' written to output file')
                
                #subdomains_list = json.dumps(subdomains_raw, indent=0, separators=('',':'))             
                #subdomains_list = subdomains_list.replace('[','').replace(']','').replace('"','')
                #print(subdomains_list)
        except Exception as e:
                print(e)
                return False

def call_find_git():
        with open('output_tester.txt') as output:
                for line in output:
                        line = line.strip()
                        print('sending '+line+' to find_git')
                        if len(line) != 0:
                                find_git(line)

def find_git(domain):
        git_list = [
        '.git/FETCH_HEAD',
        '.git/HEAD',
        '.git/ORIG_HEAD',
        '.git/config',
        '.git/info/refs',
        '.git/logs/HEAD',
        '.git/logs/refs/heads/master',
        '.git/logs/refs/remotes/origin/HEAD',
        '.git/logs/refs/remotes/origin/master',
        '.git/logs/refs/stash',
        '.git/packed-refs',
        '.git/refs/heads/master',
        '.git/refs/remotes/origin/HEAD',
        '.git/refs/remotes/origin/master',
        '.git/refs/stash',
        '.gitignore',
        '.git/COMMIT_EDITMSG',
        '.git/description',
        '.git/hooks/applypatch-msg.sample',
        '.git/hooks/applypatch-msg.sample',
        '.git/hooks/applypatch-msg.sample',
        '.git/hooks/commit-msg.sample',
        '.git/hooks/post-commit.sample',
        '.git/hooks/post-receive.sample',
        '.git/hooks/post-update.sample',
        '.git/hooks/pre-applypatch.sample',
        '.git/hooks/pre-commit.sample',
        '.git/hooks/pre-push.sample',
        '.git/hooks/pre-rebase.sample',
        '.git/hooks/pre-receive.sample',
        '.git/hooks/prepare-commit-msg.sample',
        '.git/hooks/update.sample',
        '.git/index',
        '.git/info/exclude',
        '.git/objects/info/packs',]
        for item in git_list:
                item = item.strip()
                try:
                        response_raw = urllib.request.urlopen('http://'+domain+'/'+item)
                        response_dict = json.loads(response_raw.read())
                        print(item+' -> '+response_dict)
                except Exception as e:
                        print('--------------------http://'+domain+'/'+item+'--------------------')
                        print(e)
        
if __name__ == "__main__":
        input_file_name = str(sys.argv[1])
        with open(input_file_name,'r') as input:
            for target in input:
                    target = target.strip()
                    do_parse(target)
        call_find_git()
        #target = str(sys.argv[1])
        #do_parse(target)  