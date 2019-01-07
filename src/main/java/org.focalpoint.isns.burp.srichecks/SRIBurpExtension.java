package org.focalpoint.isns.burp.srichecks;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IScannerCheck;
import burp.IExtensionHelpers;
import burp.IScanIssue;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IScannerInsertionPoint;
import burp.ITab;
import java.awt.Component;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.focalpoint.isns.burp.srichecks.ScriptFinder;
import org.focalpoint.isns.burp.srichecks.IoCChecker;
import org.focalpoint.isns.burp.srichecks.JavascriptResource;
import org.focalpoint.isns.burp.srichecks.PluginConfigurationTab;

import javax.swing.SwingUtilities;

public class SRIBurpExtension implements IBurpExtender, IScannerCheck, ITab
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private IoCChecker iocChecker = new IoCChecker();
    private Integer scanNumber = 0;

    private PluginConfigurationTab panel;

    //
    // implement IBurpExtender
    //
    
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;
        
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        
        // set our extension name
        callbacks.setExtensionName("Focal Point Scan Checks -- SRI and JavaScript Threat Intel");
        
        // register ourselves as a custom scanner check
        callbacks.registerScannerCheck(this);

        // Create teh config tab
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                // main panel
                panel = PluginConfigurationTab.getInstance();
                panel.render();
                callbacks.customizeUiComponent(panel);

                // add the custom tab to Burp's UI
                callbacks.addSuiteTab(SRIBurpExtension.this);
            }
        });
    }

	@Override
	public String getTabCaption() {
		return "Focal Point SRI";
	}

	@Override
	public Component getUiComponent() {
		return panel;
	}

    // helper method to search a response for occurrences of a literal match string
    // and return a list of start/end offsets
    private List<int[]> getMatches(byte[] response, byte[] match)
    {
        List<int[]> matches = new ArrayList<int[]>();

        int start = 0;
        while (start < response.length)
        {
            start = helpers.indexOf(response, match, true, start, response.length);
            if (start == -1)
                break;
            matches.add(new int[] { start, start + match.length });
            start += match.length;
        }
        
        return matches;
    }

    // Check for Cross-Domain Script Includes (DOM)
    public List<IScanIssue> checkCspForSriRequirements(IHttpRequestResponse baseRequestResponse){
        List<IScanIssue> issues = new ArrayList<>();
        String response = helpers.bytesToString(baseRequestResponse.getResponse());
        if (!response.contains("Content-Security-Policy: require-sri-for script;")){
            issues.add(
                new CustomScanIssue(
                    baseRequestResponse.getHttpService(), 
                    helpers.analyzeRequest(baseRequestResponse).getUrl(), 
                    null, // No way to highlight this, 
                    "Content Security Policy does not Require Subresource Integrity",
                    "The content security policy provided in the response headers does not require subresource integrity for script elements. Content security policies may do so by returning the following header:<br/><pre>Content-Security-Policy: require-sri-for script;</pre>",
                    "Low",
                    "<p>When a script is served from a third-party source such as a public Content Delivery Network (CDN) location, the 'integrity' attribute of the 'script' tag should be used to confirm that the script can be trusted (i.e., it has not been modified from a version known to include only intended functionality and not be malicious). This attribute instructs the browser to load the third-party script, generate a hash of the file, and validate that its hash matches the hash of the exact version of the script known to be trusted before it can be executed. If the hash of the script loaded from the third-party source does not match the hash of the trusted version, most modern browsers will block the script's execution.</p><p>In order to enforce the use of subresource integrity for all scripts used across a site, the 'require-sri-for script' Content-Security-Policy directive should be used to instruct the browser to validate that the 'integrity' attribute is in place for all script elements.</p>"
                )
            );
        }
        return issues;
    }

    // Check for Cross-Domain Script Includes (DOM)
    public List<IScanIssue> checkForCrossDomainScriptIncludesDom(IHttpRequestResponse baseRequestResponse, ScriptFinder finder){
        List<IScanIssue> issues = new ArrayList<>();
        if (finder.getCrossDomainDomScripts().size() > 0){
            String scriptString = "";
            for (String scriptUrl : finder.getCrossDomainDomScripts()){
                scriptString += "<li>" + scriptUrl + "</li>";
            }
            issues.add(
                new CustomScanIssue(
                    baseRequestResponse.getHttpService(), 
                    helpers.analyzeRequest(baseRequestResponse).getUrl(), 
                    null, // No way to highlight this, 
                    "Cross-Domain Script Includes (DOM)",
                    "The following cross-domain JavaScript resources were loaded in to the DOM but were not present in the initial page: <br/><ul>" + scriptString + "</ul>",
                    "Medium",
                    "<p>When an application includes a script from an external domain, this script is executed by the browser within the security context of the invoking application. The script can therefore do anything that the application's own scripts can do, such as loading additional third-party scripts into DOM, accessing application data, and performing actions within the context of the current user.</p><p>If you include a script from an external domain, then you are trusting that domain with the data and functionality of your application, and you are trusting the domain's own security to prevent an attacker from modifying the script to perform malicious actions within your application.</p>"
                )
            );
        }
        return issues;
    }

    // Check for Cross-Domain Script Includes (DOM)
    public List<IScanIssue> checkForSriIssues(IHttpRequestResponse baseRequestResponse, ScriptFinder finder){
        List<IScanIssue> issues = new ArrayList<>();
        List<String> sriScripts = new ArrayList<>();
        List<String> sriMissingScripts = new ArrayList<>();
        // Go through all of the scripts and find those which have an integrity attribute and those which don't.
        for (String scriptUrl : finder.getScripts()){
            String tag = finder.getHtmlTagFor(scriptUrl);
            if (tag.contains("integrity=\"sha")){
                sriScripts.add(scriptUrl);
            }
            else {
                sriMissingScripts.add(scriptUrl);
            }
        }
        if (sriMissingScripts.size() > 0){
            // There are scripts missing SRI. Need to log an issue.
            for (String scriptUrl : sriMissingScripts){
                List<int[]> matches = getMatches(baseRequestResponse.getResponse(), finder.getHtmlTagFor(scriptUrl).getBytes());
                issues.add(
                    new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        helpers.analyzeRequest(baseRequestResponse).getUrl(), 
                        new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, matches) }, 
                        "JavaScript Element Missing Subresource Integrity Attribute",
                        "The following script references were present within the HTML or the DOM after loading and do not leverage an 'integrity' attribute to establish subresource integrity: <br/><ul><li>" + scriptUrl + "</li></ul>",
                        "Low",
                        "<p>When a script is served from a third-party source such as a public Content Delivery Network (CDN) location, the 'integrity' attribute of the 'script' tag should be used to confirm that the script can be trusted (i.e., it has not been modified from a version known to include only intended functionality and not be malicious). This attribute instructs the browser to load the third-party script, generate a hash of the file, and validate that its hash matches the hash of the exact version of the script known to be trusted before it can be executed. If the hash of the script loaded from the third-party source does not match the hash of the trusted version, most modern browsers will block the script's execution.</p><p>In order to enforce the use of subresource integrity for all scripts used across a site, the 'require-sri-for script' Content-Security-Policy directive should be used to instruct the browser to validate that the 'integrity' attribute is in place for all script elements.</p>"
                    )
                );
            }
        }

        if (sriScripts.size() > 0){
            // For all of the resources which use SRI attributes, check the hash
            for (String scriptUrl: sriScripts){
                if (!finder.getScriptObjectFor(scriptUrl).checkIntegrity()){
                    // Integrity check failed
                    List<int[]> matches = getMatches(baseRequestResponse.getResponse(), finder.getHtmlTagFor(scriptUrl).getBytes());
                    issues.add(
                        new CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            helpers.analyzeRequest(baseRequestResponse).getUrl(), 
                            new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, matches) }, 
                            "JavaScript Subresource Integrity Failure",
                            "The following script references utilize subresource integrity, however the hash provided in the integrity attribute does not match the hash of the JavaScript obtained from the URL: <br/><ul><li>" + scriptUrl + "</li></ul>",
                            "High",
                            "<p>When a script is served from a third-party source such as a public Content Delivery Network (CDN) location, the 'integrity' attribute of the 'script' tag should be used to confirm that the script can be trusted (i.e., it has not been modified from a version known to include only intended functionality and not be malicious). This attribute instructs the browser to load the third-party script, generate a hash of the file, and validate that its hash matches the hash of the exact version of the script known to be trusted before it can be executed. If the hash of the script loaded from the third-party source does not match the hash of the trusted version, most modern browsers will block the script's execution.</p><p>In order to enforce the use of subresource integrity for all scripts used across a site, the 'require-sri-for script' Content-Security-Policy directive should be used to instruct the browser to validate that the 'integrity' attribute is in place for all script elements.</p>"
                        )
                    );
                }
            }
        }

        return issues;
    }

    // Check for Cross-Domain Script Includes (DOM)
    public List<IScanIssue> checkJavaScriptThreatIntel(IHttpRequestResponse baseRequestResponse, ScriptFinder finder){
        List<IScanIssue> issues = new ArrayList<>();
        for (String scriptUrl : finder.getScripts()){
            JavascriptResource scriptObject = finder.getScriptObjectFor(scriptUrl);
            // Check for known, bad JavaScript hashes
            if (iocChecker.checkHashes(scriptObject.getHashes())){
                // This is a bad resource based on the hash
                List<int[]> matches = getMatches(baseRequestResponse.getResponse(), finder.getHtmlTagFor(scriptUrl).getBytes());
                issues.add(
                    new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        helpers.analyzeRequest(baseRequestResponse).getUrl(), 
                        new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, matches) }, 
                        "Possibly Compromised JavaScript (Hash IoC)",
                        "The JavaScript at " + scriptUrl + " is a known, compromised resource based on the following threat intelligence source:<ul><li>" + iocChecker.getHashesSource(scriptObject.getHashes()) + "</li></ul>",
                        "High",
                        "<p>When a script is served from a third-party source such as a public Content Delivery Network (CDN) location, the 'integrity' attribute of the 'script' tag should be used to confirm that the script can be trusted (i.e., it has not been modified from a version known to include only intended functionality and not be malicious). This attribute instructs the browser to load the third-party script, generate a hash of the file, and validate that its hash matches the hash of the exact version of the script known to be trusted before it can be executed. If the hash of the script loaded from the third-party source does not match the hash of the trusted version, most modern browsers will block the script's execution.</p><p>In order to enforce the use of subresource integrity for all scripts used across a site, the 'require-sri-for script' Content-Security-Policy directive should be used to instruct the browser to validate that the 'integrity' attribute is in place for all script elements.</p>"
                    )
                );
            }
            // Check for known, bad JavaScript paths
            if (iocChecker.checkUrl(scriptUrl)){
                // This is a bad resource based on the path
                List<int[]> matches = getMatches(baseRequestResponse.getResponse(), finder.getHtmlTagFor(scriptUrl).getBytes());
                issues.add(
                    new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        helpers.analyzeRequest(baseRequestResponse).getUrl(), 
                        new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, matches) }, 
                        "Possibly Compromised JavaScript (URL IoC)",
                        "The JavaScript at " + scriptUrl + " is a known, compromised resource based on the following threat intelligence source:<ul><li>" + iocChecker.getUrlSource(scriptUrl) + "</li></ul>",
                        "High",
                        "<p>When a script is served from a third-party source such as a public Content Delivery Network (CDN) location, the 'integrity' attribute of the 'script' tag should be used to confirm that the script can be trusted (i.e., it has not been modified from a version known to include only intended functionality and not be malicious). This attribute instructs the browser to load the third-party script, generate a hash of the file, and validate that its hash matches the hash of the exact version of the script known to be trusted before it can be executed. If the hash of the script loaded from the third-party source does not match the hash of the trusted version, most modern browsers will block the script's execution.</p><p>In order to enforce the use of subresource integrity for all scripts used across a site, the 'require-sri-for script' Content-Security-Policy directive should be used to instruct the browser to validate that the 'integrity' attribute is in place for all script elements.</p>"
                    )
                );
            }
        }
        
        return issues;
    }

    private void log(String urlString, String logString){
        System.out.println("[FOPO-SRI][" + scanNumber + "] " + urlString + " - " + logString);
    }

    //
    // implement IScannerCheck
    //
    
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse)
    {
        scanNumber += 1;
        // Create the issues array
        List<IScanIssue> issues = new ArrayList<>();
        // Create a script finder for this instance
        ScriptFinder scriptFinder = new ScriptFinder();
        // Find the URL
        String url = helpers.analyzeRequest(baseRequestResponse).getUrl().toString();
        // Get the response contents for the passive scan
        String response = helpers.bytesToString(baseRequestResponse.getResponse());
        String html = "";
        
        log(url, "starting passive checks.");

        if (url.endsWith(".js")){
            // This is a JavaScript resource and I don't need to check it
            log(url,"finished passive checks - not checking a JS file.");
            return issues;
        }

        if (!response.contains("<script")){
            // This has no script resource and I don't need to check it
            log(url,"finished passive checks - not checking a resource with no script tags.");
            return issues;
        }

        scriptFinder.setUrl(url);
        // Is there actual HTML in the response?
        Pattern pattern = Pattern.compile("<\\s*html[^>]*>([\\s\\S]*)<\\s*/\\s*html>");
        Matcher matcher = pattern.matcher(response);
        if (matcher.find()){
            html = matcher.group(0);
            scriptFinder.setHtml(html);
            log(url,"loading DOM in passive check.");
            scriptFinder.checkForDomScripts();
            // Perform checks which require the DOM
            issues.addAll(checkForCrossDomainScriptIncludesDom(baseRequestResponse, scriptFinder));
        }
        else {
            scriptFinder.setHtml(response);
        }

        // Now we can check the scripts
	    log(url,"checking for SRI CSP requirements.");
        issues.addAll(checkCspForSriRequirements(baseRequestResponse));
	    log(url,"checking for SRI issues.");
        issues.addAll(checkForSriIssues(baseRequestResponse, scriptFinder));
	    log(url,"checking JavaScript resources against threat intel.");
        issues.addAll(checkJavaScriptThreatIntel(baseRequestResponse, scriptFinder));
	    log(url,"checks complete!");

        if (issues.size() > 0){
            return issues;
        }
        else {
            return null;
        }
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint)
    {
        // Empty capability
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue)
    {
        // This method is called when multiple issues are reported for the same URL 
        // path by the same extension-provided check. The value we return from this 
        // method determines how/whether Burp consolidates the multiple issues
        // to prevent duplication
        //
        // Since the issue name is sufficient to identify our issues as different,
        // if both issues have the same name, only report the existing issue
        // otherwise report both issues
        if (existingIssue.getIssueName().equals(newIssue.getIssueName()))
            return -1;
        else return 0;
    }
}

//
// class implementing IScanIssue to hold our custom scan issue details
//
class CustomScanIssue implements IScanIssue
{
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String severity;
    private String issueBackground;
    private String remediationBackground; // not wired
    private String remediationDetail; // not wired
    private Integer issueType = 134217728;

    public CustomScanIssue(
            IHttpService httpService,
            URL url, 
            IHttpRequestResponse[] httpMessages, 
            String name,
            String detail,
            String severity,
            String background)
    {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.detail = detail;
        this.severity = severity;
        this.issueBackground = background;
    }
    
    @Override
    public URL getUrl()
    {
        return url;
    }

    @Override
    public String getIssueName()
    {
        return name;
    }

    @Override
    public int getIssueType()
    {
        return 0;
    }

    @Override
    public String getSeverity()
    {
        return severity;
    }

    @Override
    public String getConfidence()
    {
        return "Certain";
    }

    @Override
    public String getIssueBackground()
    {
        return issueBackground;
    }

    @Override
    public String getRemediationBackground()
    {
        return null;
    }

    @Override
    public String getIssueDetail()
    {
        return detail;
    }

    @Override
    public String getRemediationDetail()
    {
        return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages()
    {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService()
    {
        return httpService;
    }
    
}
