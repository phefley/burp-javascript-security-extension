# Focal Point JavaScript Burp Extension
This is a burp extension which adds passive checks to the Burp scanner. The following is a list of items it will look for:

  - Cross-Domain Script Includes (DOM)
  - JavaScript Missing Subresource Integrity Attributes
  - CORS Headers Do Not Require Subresource Integrity
  - Malicious/Vulnerable JavaScript Includes
  - Subresource Integrity Failed Validation

It does this by looking at the HTML received and loads the DOM via a headless Chromium instance using Selenium.

## Installation
1. Obtain a copy of this repo.
2. Install the chromedriver shim between selenium and chromium. On Ubuntu, this is done by issuing the following command: 
   ```sudo apt install chromium-chromedriver```
3. In burp, go to the extender tab, extensions sub-tab, and Add this extension. It is a Java extension type and you will need to select the org-focalpoint-isns-burp-srichecks.jar file.

## Configuration
A "Focal Point SRI" tab will appear in your burp session which allows you to configure two things:
- The path to the chromedriver binary you want to use. This defaults to the standard location it is installed to in Linux.
- The delay before evaluating the DOM (in seconds). As all of the JavaScript is gathered and run, the DOM may change over time. For advanced pages or slow connections, you might want to bump this up, but passive scans will take longer. The default, which I've had luck with, is 10 seconds.

## Execution
When you run passive checks, the checks installed will run. Any output or errors will appear on the Extender/Extensions tab under "Focal Point - Custom Scanner Checks".

## Requirements
1. watch the DOM (not "html") and log every loaded JS as a finding (medium?). totally ignore scope
2. check every loaded js against a list of known compromised and make different alert
3. profit
4. [pending] When you can't load a JS resource, check to see if the domain is available. 


## References
 - https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
 - https://github.com/PortSwigger/example-scanner-checks/blob/master/python/CustomScannerChecks.py
