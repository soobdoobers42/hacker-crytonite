<!-- ABOUT THE PROJECT -->
## Honeypwned

<p align="center">
  <img width="598" height="346" src="https://github.com/lmaoggrofl/honeypwned/assets/110363544/83c449b1-f5a8-4bba-b06d-00d1e235b076">
</p>

Honeypwned is a low interaction honeypot that can emulate specific services or protocols, such as SSH and HTTP
designed to counter the vulnerabilities and misuse of Virtual Private Networks (VPNs). 
As VPNs have gained popularity for enhancing online security and privacy, they've also been utilized by malicious actors to conceal their identities. 
Positioned strategically within the DMZ, Honeypwned operates as a honeypot, luring in these threat actors with enticing files. 
Once engaged, Honeypwned exposes their true identities, effectively mitigating cybersecurity risks

<!-- GETTING STARTED -->
## Getting Started

This is an example of how you can set up your project locally.
Download a local copy up and follow these steps below.

### Prerequisites

* Linux OS
* Python Libraries
```shell
sudo pip3 install -r requirements.txt
```
```shell
sudo apt install python3-tk
```

### Usage and Setting up

1. Download the repo as a zip or clone the repo
   ```shell
   git clone https://github.com/soobdoobers42/hacker-crytonite.git
   ```
2. Install libraries and tkinter shown in the prerequisites
3. Change the IP in scripts/PDFViewerPayload.py and then run the command below
   ```shell
   cd hacker-crytonite/scripts
   nano PDFViewerPayload.py
   ```
   ```shell
   pyinstaller --onefile --name PDFViewer PDFViewerPayload.py
   ```
4. Navigate to dist, zip the payload and replace the current zip in static/tools/
   ```shell
   cd dist
   zip PDFViewer.zip PDFViewer
   rm -rf ../static/tools/PDFViewer.zip
   mv PDFViewer.zip ../static/tools/PDFViewer.zip
   ```
5. Open config.ini to change the ports you want to open for the honeypot (make sure port 80 and 8888 are open)
6. Save the config file
7. Run the honeypot (make sure to run as privd user)
   ```python
   sudo python3 main.py
   ```
8. Listen to any traffic interacting with ports that you set open
9. If someone with a VPN downloads and run the payload, you will see their true IP
