# JavaScript Security Burp Extension
This is a burp extension which adds passive checks to the Burp scanner. The following is a list of items it will look for:

  - Cross-Domain Script Includes (DOM)
  - JavaScript Missing Subresource Integrity Attributes
  - CSP Headers Do Not Require Subresource Integrity
  - Malicious/Vulnerable JavaScript Includes
  - Subresource Integrity Failed Validation
  - Cross-Domain Script Includes where DNS Resolution Fails

It does this by looking at the HTML received and loads the DOM via a headless Chromium instance using Selenium.

## Licensing and Recognition
Distributed under GPLv3.
Copyright 2019: Focal Point Data Risk, LLC
Written by: Peter Hefley

## Installation
1. Obtain a copy of this repo.
2. Ensure that Chrome/Chromium is installed in a standard location.
3. Obtain the appropriate chromedriver for your OS and version of Chrome (see: http://chromedriver.chromium.org/downloads/version-selection). Note the file location.
4. In burp, go to the extender tab, extensions sub-tab, and Add this extension. It is a Java extension type and you will need to select the included, or built, jar file.
5. Once started, select the "JavaScript Security" tab and set the correct chrome driver location.

## Configuration
A "JavaScript Security" tab will appear in your burp session which allows you to configure two things:
- The path to the chromedriver binary you want to use. This defaults to the bundled version appropriate for your operating system. Setting a chromedriver here will override the default.
- The delay before evaluating the DOM (in seconds). As all of the JavaScript is gathered and run, the DOM may change over time. For advanced pages or slow connections, you might want to bump this up, but passive scans will take longer. The default, which I've had luck with, is 10 seconds.

It is possible to load indicators of compromise (IOCs) as JSON files through the GUI tab. Examples are provided in the intel folder.

## Execution
When you run passive checks, the checks installed will run. Any output or errors will appear on the Extender/Extensions tab under "JavaScript Security -- SRI and Threat Intel".

## Requirements
1. watch the DOM (not "html") and log every loaded JS as a finding (medium?). totally ignore scope
2. check every loaded js against a list of known compromised and make different alert
3. profit
4. When you can't load a JS resource, check to see if the domain is available. 


## Known Issues
I've seen weird caching issues with systemd-resolved, the default DNS service on Ubuntu. If you see resources which cannot be accessed due to DNS issues, consider disabling the DNS caching or clearing your cache. Both seem to help.

```/etc/systemd > cat resolved.conf  | grep "Cache"```

```Cache=no```

When you change your version of Chrome, you will also need to change your version of ChromeDriver, now. Google no longer supports drivers for a range of chrome versions. See http://chromedriver.chromium.org/downloads/version-selection


## References
 - https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
 - https://chromedriver.chromium.org/capabilities
 
