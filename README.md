# IPURL Tool

## Table of Contents

- [About](#About)
- [Requirements](#Requirements)
  - [python3](#python3)
  - [PyQT6](#pyqt6)
  - [Requests](#requests)
- [How to use](#How-to-use)
- [Free API Limitations](#Free-API-Limitations)
  - [VirusTotal API](#VirusTotal-API)
  - [AbuseIPDB](#AbuseIPDB)
- [Screenshots](#Screenshots)
- [Future Updates](#Future-Updates)


## About 

Simple macOS tool to help SOC and other blueteamers/cybersecurity professionals. You can use the tool to perform nslookup, ping, whois searches, search for URL reputation with VirusTotal integration, and search for IP address reputation via AbuseIPDB

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


## How to use

1) First, install all requirements under [requirements](#requirements)
2) Obtain a VirusTotal Free API Key, and add the API Key to ____ of main.py. (More info on dependencies.md)
3) Obtain an AbuseIPD Free API Key, and add the API Key to line ___ of main.py (More info on dependencies.md)
4) <ins>**If Windows**</ins>, in line ____ of main.py, remove ``` -c 5 ``` .
5) Run main.py from the directory it is stored using  ``` python3 main.py ```

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

- [ ] Format json return from VirusTotal and AbuseIPDB integrations
- [ ] OS check coded to be compatible with Windows
- [ ] Multiple inputs at once
