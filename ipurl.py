## 1 Meta

# Author: spapjh (github.com/spapjh)
# Date: June 2022
# Update Log:

## 2 Imports and APIs

import sys
import os
from unittest import result
import whois
from PyQt6.QtWidgets import (QApplication, QPushButton, QWidget, QLineEdit, QGridLayout, QPlainTextEdit)                            
import json
import requests





## 3 Application 

# 3. 1 GUI

class MyApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('IPURL TOOL') #setting window title
        self.resize(800, 450) #setting width,height of main window
        

        # Widgets 

        self.inputIPadd = QLineEdit()
        self.inputIPadd.setPlaceholderText("Enter IP address or URL without www.")


        # nslookupButton
        self.nslookupbutton = QPushButton()
        self.nslookupbutton.setText("nslookup")
        self.nslookupbutton.clicked.connect(self.nslookupbuttonclicked)

        # pingButton
        self.pingbutton = QPushButton()
        self.pingbutton.setText("ping")
        self.pingbutton.clicked.connect(self.pingbuttonclicked)


        #Whois Button
        self.whoisbutton = QPushButton()
        self.whoisbutton.setText("WHOIS Search (URL/IP Address)")
        self.whoisbutton.clicked.connect(self.whoisbuttonclicked)
        
        
        # URL Reputation Button
        self.urlreputationbutton = QPushButton()
        self.urlreputationbutton.setText("Search URL Reputation via VirusTotal")
        self.urlreputationbutton.clicked.connect(self.urlreputatiobuttonclicked)

        #IP Reputation Button
        self.reputationdbutton = QPushButton()
        self.reputationdbutton.setText("Search IP Address Reputation via AbuseIPDB")
        self.reputationdbutton.clicked.connect(self.reputationclicked)

        # Output box to display all results (plain text box)
        self.output = QPlainTextEdit()


        #Setting Layout Manager and assigning the layout to the parent widget
        layout = QGridLayout()
        self.setLayout(layout)


        #Adding Widgets to Layout Manager (adding from row, from column, rowspan and column span)
        
        layout.addWidget(self.inputIPadd)
        layout.addWidget(self.nslookupbutton)
        layout.addWidget(self.pingbutton)
        layout.addWidget(self.whoisbutton)
        layout.addWidget(self.urlreputationbutton)
        layout.addWidget(self.reputationdbutton)
        layout.addWidget(self.output)

        


    ## 3. 2 Defs

    #3.2.1.  Def for when ping/nslookup button is clicked.  self.inputIPadd.text() is the content of the inputIPadd QLineEdit widget. Click is linked to pingnslookup .  
    # Result is set to display on plaintext widget named output.
    def nslookupbuttonclicked(self):
        result = self.nslookup(host=self.inputIPadd.text())
        self.output.setPlainText(result)


    def pingbuttonclicked(self):
        result = self.pingsearch(host=self.inputIPadd.text())
        self.output.setPlainText(result)


    #3.2.2 Def for when WhoIs button is clicked.  self.inputIPadd.text() is the content of the inputIPadd QLineEdit widget. Click is linked to whoissearch_ .  
    # Result is set to display on plaintext widget named output.
    def whoisbuttonclicked(self):
        result = self.whoissearch_(host=self.inputIPadd.text())
        self.output.setPlainText(result)

    #3.3.3 Def for when Block button is clicked. self.inputIPadd.text() is the content of the inputIPadd QLineEdit widget. Click is linked to blocksearch. 
    # Result is set to display on plaintext widget named output.
    def urlreputatiobuttonclicked(self):
        result = self.urlreputationsearch(host=self.inputIPadd.text())
        self.output.setPlainText(result)

    #3.3.4 Def for when Reputation button is clicked. self.inputIPadd.text() is the context of the inputIPadd QLineEdit widget. 
    # Click is linked to reputation search. Result is set to display on plaintext widget named output.
    def reputationclicked(self):
        result = self.reputationsearch(host=self.inputIPadd.text())
        self.output.setPlainText(result)

    #3.3.5 Def for Whois Search. Fields of interest to be returned are specified.
    def whoissearch_(self, host):
        res = whois.whois(host)
        return(f"Domain name: {res.domain_name}, Registrar: {res.registrar}, Creation Date: {res.creation_date}, Contact Email: {res.emails}, City and Country: {res.city}{res.country}")

    #3.3.6 Def for URL reputation search. Leverages VirusToital Free API (500/daily and 4/minute limit)
    def urlreputationsearch (self, host):
        
        api_url = 'https://www.virustotal.com/vtapi/v2/url/report'
    
        params = {
            'apikey': '(PLACE VIRUSTOTALAPI HERE)',
            'resource': host,
            'scan': 0
        }
        response = requests.get(api_url, params=params)
        if response.status_code == 200:
         data = response.json()
         scans = data.get('scans')
         temp_string = f'Link to VT Search: {data.get("permalink")}\n, URL Scanned: {data.get("resource")}\n, Scan Date: {data.get("scan_date")}\n, AV/DBs that reported domain as Malicious: {data.get("positives")}\n '
         for name, value in scans.items():
                result = value.get('result')
                temp_string = temp_string + f'\t{name}: {result}\n'
         return(temp_string)

       
    #3.3.7 Def for IP reputation search. Leverages AbuseIPDB Free API (1k/daily limit)
    def reputationsearch (self,host):
        url = 'https://api.abuseipdb.com/api/v2/check'
        querystring = {
            'ipAddress': (host),
            'maxAgeInDays': '90'
        }

        headers = {
            'Accept': 'application/json',
            'Key': '(PLACE ABUSEPIDB API HERE)'
        }

        response = requests.get(url=url, headers=headers, params=querystring)
        data = response.json().get('data')
        formatedanswer = f'Domain/Provider Associated with IP: {data.get("domain")}\n, IP Address: {data.get("ipAddress")}\n, Country: {data.get("countryCode")}\n, Abuse Confidence Score (0=None 100=Max): {data.get("abuseConfidenceScore")}\n, Times this IP has been reported: {data.get("totalReports")}\n, Last time this IP was reported: {data.get("lastReportedAt")}\n  '
        return(formatedanswer)

    #3.3.8 Def for ping/nslookup 
    def nslookup(self, host):
        nslookupresponse = (os.popen(f'nslookup {host}').read())
        return(nslookupresponse)


    def pingsearch(self,host):
        pingresponse = (os.popen(f'ping {host} -c 5').read())
        return(pingresponse)

# Creating QApplication
app = QApplication(sys.argv)

window = MyApp()
window.show()
app.exec()
