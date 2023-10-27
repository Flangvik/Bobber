# Bobber - Bounces when a fish bites!
If it can be automated, it should be automated! Bobber will monitor a given Evilginx database file for changes, and if a valid Evilginx session complete with a captured cookie is found, Bobber will utilize the RoadTools RoadTX library to retrieve the access and refresh token for the user, then optionally trigger TeamFiltration to exfiltrate all the sweet, sweet loot. Bobber supports monitoring a local file path or a file path on a remote host through SSH.

Bobber accepts a number of input arguments to adjust the RoadTools interactive auth flow, selection between key and credentials-based SSH auth, as well as the added benefit of getting pushover notifications once a user submits their credentials and the loot is on the way.

