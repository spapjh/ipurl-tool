# IPURL Tool

## Table of Contents

- [About](#About)
- [Requirements](#Requirements)
  - [python3](#python3)
  - [PyQT6](#pyqt6)
  - [Requests](#requests)
  - [VirusTotal Free API](#Virustotal-Free-API)
  - [AbuseIPDB Free API](#AbuseIPDB-Free-API)
- [How to use](#How-to-use)
- [Free API Limitations](#Free-API-Limitations)
  - [VirusTotal API](#VirusTotal-API)
  - [AbuseIPDB](#AbuseIPDB)
- [Screenshots](#Screenshots)
- [Future Updates](#Future-Updates)


## About 

Simple macOS tool to help SOC and other blueteamers/cybersecurity professionals. You can use the tool to perform nslookup, ping, whois searches, search for URL reputation with VirusTotal integration, and search for IP address reputation via AbuseIPDB.

WINDOWS INFORMATION: In its current version, whois function does not work if in Windows, and a small modification listed in [how to use](#how-to-use) is needed for ping to work correctly. 

## Requirements

### python3

More information on how to install python: https://www.python.org/downloads/

### PyQT6

Via Terminal

``` pip install pyqt6 ```

More information on how to install PyQT6 module: https://www.pypi.org/project/PyQT6/


### Requests

Via Terminal

``` pip install requests ```

More information on how to install requests module: https://www.pypi.org/project/requests/


### VirusTotal Free API

How to get VirusTotal Free API
  - Visit: https://www.virustotal.com/gui/join-us
  - Register for a VirusTotal account or log into your account if already created
 
 
Once registered, do the following for ipurl to work as intended:
  - Once logged into your VirusTotal account, navigate to the API Key section of your profile
  - Copy your API Key value
  - Paste your VirusTotal Free API key into ``` line 130 ``` of ``` ipurl.py ```

For more information on VirusTotal API visit: https://developers.virustotal.com/reference/overview


### AbuseIPDB Free API

How to get AbuseIPDB Free API
  - Visit https://www.abuseipdb.com/register
  - Register for an AbuseIPDBd account or log into your account if already created
  
Once registered, do the following for ipurl to work as intended:
  - Once loggedinto your AbuseIPDB account, navigate to the API section of your profile
  - Create an API Key, name it as you please, and copy your new API key value
  - Paste your AbuseIPDB Free API key into ``` line 155 ``` of ``` ipurl.py ```
  

For more information on AbuseIPDB API visit: https://www.abuseipdb.com/api.html

## How to use

1) First, install all requirements under [requirements](#requirements) and download ``` ipurl.py ``` from this repo
2) Obtain a VirusTotal Free API Key, and add the API Key to ``` line 130 ``` of ``` ipurl.py.``` (More info under [requirements](#requirements))
3) Obtain an AbuseIPD Free API Key, and add the API Key to ``` line 155 ``` of ``` ipurl.py ```  (More info under [requirements](#requirements))
4) <ins>**If Windows**</ins>, in line ____ of main.py, remove ``` -c 5 ``` .
5) Run ipurl.py from the directory it is stored using  ``` python3 ipurl.py ```

## Free API Limitations


### VirusTotal API

- Request Rate: 4 lookups/main
- Daily Quota: 500 lookups/day
- Monthly Quota: 15.5k lookups/month


### AbuseIPDB

- 1,000 checks/daily

More info: https://www.abuseipdb.com/register



## Screenshots

![whois](/readmeimgs/whois.png)

![abuseipdb](/readmeimgs/AbuseIPDB.png)


## Future Updates

- [X] Format json return from VirusTotal and AbuseIPDB integrations
- [ ] OS check coded to be fully compatible with Windows
- [ ] Multiple inputs at once / Ability to take .csv and .txt files as input
