/**
 * BurpSuite JavaScript Security Extension
 * Copyright (C) 2019  Peter Hefley
 * 
 * This program is free software: you can redistribute it and/or modify it under the terms of the GNU General 
 * Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the 
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for 
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along with this program.  
 * If not, see <https://www.gnu.org/licenses/>.
 */
package org.focalpoint.isns.burp.srichecks;

import org.focalpoint.isns.burp.srichecks.JavascriptResource;

import burp.IBurpExtenderCallbacks;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.support.ui.ExpectedCondition;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.openqa.selenium.StaleElementReferenceException;
import org.openqa.selenium.TimeoutException;
import java.util.concurrent.TimeUnit;

import jdk.incubator.http.HttpClient;
import jdk.incubator.http.HttpRequest;
import jdk.incubator.http.HttpResponse;
import jdk.incubator.http.HttpResponse.BodyHandler;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import java.util.List;
import java.net.URL;
import java.net.URI;
import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.HashMap;

public class ScriptFinder{
    private IBurpExtenderCallbacks myCallbacks;
    private Integer PAGE_WAIT_TIMEOUT = 10;
    private String url="NONE";
    private String html;
    private String driverPath = "";
    private List<String> domScripts = new ArrayList<>();
    private List<String> htmlScripts = new ArrayList<>();
    // Something to store a parsed URL
    private URL parsedUrl;
    // A webdriver object
    private WebDriver driver;
    // A dictionary of dom and html script data, respectively
    private HashMap<String,JavascriptResource> domScriptData = new HashMap<String,JavascriptResource>();
    private HashMap<String,JavascriptResource> htmlScriptData = new HashMap<String,JavascriptResource>();

    /**
     * Set the Burp Suite callbacks object to be used
     * @param callbacks the burp suite callbacks object to use for the HTTP interface
     */
    public void setCallbacks(IBurpExtenderCallbacks callbacks){
        myCallbacks = callbacks;
    }

    /**
     * Set the URL to be evaluated for JavaScript resources
     * @param urlString a String of the URL to be evaluated
     */
    public void setUrl(String urlString){
        url = urlString;
        try {
            parsedUrl = new URL(urlString);
        }
        catch (Exception e) {
            System.err.println("[-] Could not parse URL: " + urlString);
        }
    }

    /**
     * Get the URL being evaluated by this object
     * @return a string of the URL evaluated
     */
    public String getUrl(){
        return url;
    }

    /**
     * Set the delay, or timeout, for Selenium to wait and load everything
     * @param timeoutInSeconds an integer value of how many seconds to wait
     */
    public void setTimeout(Integer timeoutInSeconds){
        PAGE_WAIT_TIMEOUT = timeoutInSeconds;
    }

    /**
     * Get the timeout for this oject
     * @return an integer of how many seconds this object will force Selenium to wait before calling a DOM good
     */
    public Integer getTimeout(){
        return PAGE_WAIT_TIMEOUT;
    }

    /**
     * Set the chromedriver path that Selenium should use
     * @param driverPathStr a string of the path to the chromedriver binary
     */
    public void setDriverPath(String driverPathStr){
        driverPath = driverPathStr;
    }

    /**
     * Get the path of the chromedriver this object is using
     * @return a string of the path that this object is configured to use for the chromedriver binary
     */
    public String getDriverPath(){
        return driverPath;
    }

    /**
     * There is no reason that this should ever be called within burp. It is just here for tests.
     * This uses incubated JDK libraries
     */
    public void retrieveHtml(){
        if (!url.equals("NONE")){
            HttpClient client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.ALWAYS).build();
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .build();
            try {
                HttpResponse<String> response = client.send(request, BodyHandler.asString());
                setHtml(response.body());
            }
            catch (Exception ex) {
                System.err.println("[-] There was an issue getting the JavaScript file at " + url);
            }
        }
    }

    /**
     * Start the Selenium chrome driver instance with lean options
     */
    public void startDriver(){
        if (!driverPath.isEmpty()){
            ChromeOptions options = new ChromeOptions();
            options.addArguments("--headless");
            options.addArguments("--no-sandbox");
            options.addArguments("--disable-dev-shm-usage");
            HashMap<String, Object> prefs = new HashMap<String, Object>(); 
            prefs.put("profile.managed_default_content_settings.images", 2);
            options.setExperimentalOption("prefs", prefs); 
            // Remember that the default is "/usr/lib/chromium-browser/chromedriver"
            System.setProperty("webdriver.chrome.driver", driverPath);
            driver = new ChromeDriver(options);
            driver.manage().timeouts().implicitlyWait(PAGE_WAIT_TIMEOUT, TimeUnit.SECONDS); // Wait for the page to be completely loaded. Or reasonably loaded.
        }
        else {
            System.err.println("You must set a driver path before you can start a driver.");
        }
    }

    /**
     * Load the DOM and check for any referenced scripts
     * Starts and stops the selenium instance
     */
    public void checkForDomScripts(){
        startDriver();
        try{
            driver.get(url);
        }
        catch (TimeoutException e){
            System.err.println("[" + url + "][-] - timeout when connecting.");
        }
        List<WebElement> scripts = driver.findElements(By.xpath("//script"));
        for (WebElement scriptElement : scripts) {
            try {
                String src = scriptElement.getAttribute("src");
                if (!((src == null) || (src.isEmpty()))){
                    String scriptTag = scriptElement.getAttribute("outerHTML");
                    if (!domScripts.contains(src)){
                        domScripts.add(src);
                    }
                    if (!domScriptData.containsKey(src)){
                        domScriptData.put(src, new JavascriptResource(myCallbacks, src, scriptTag));
                    }
                }
            }
            catch (StaleElementReferenceException e){
                System.err.println("[" + url + "][-] - Error attempting to access a script tag on this item which is no longer in the driver DOM.");
            }
        }
        stopDriver();
    }

    /** 
     * Stop the selenium instance and kill it
     */
    public void stopDriver(){
        driver.close();
        driver.quit();
    }

    /**
     * Condition a URL to get the full protocol, FQDN, and path from any given URL with respect to the base URL
     * @param urlToCondition the URL to condition to it's full glory
     * @param baseUrl        the base URL to reference for protocol and FQDN as needed
     * @return               the full URL reconstructed as a string
     */
    private String conditionReceivedUrl(String urlToCondition, String baseUrl){ 
        try {
            URL parsedBase = new URL(baseUrl);
            try {
                URL parsedUrl = new URL(urlToCondition);
                return parsedUrl.toString();
            }
            catch (MalformedURLException e){
                if ((urlToCondition.startsWith("/")) && (!urlToCondition.startsWith("//"))) {
                    // This is probably just a path. Let's try setting that.
                    try {
                        URL parsedPathUrl = new URL(parsedBase.getProtocol(), parsedBase.getHost(), parsedBase.getPort(), urlToCondition);
                        return parsedPathUrl.toString();
                    }
                    catch (MalformedURLException e1){
                        System.err.println("[-] Could not parse URL " + urlToCondition + " by attempting to parse it as a path.");
                        return null;
                    }
                }
                else {
                    if (urlToCondition.startsWith("//")){
                        // This should use the same protocol, but everything else should change
                        try {
                            String newUrl = parsedBase.getProtocol() + ":" + urlToCondition;
                            URL parsedProtocolURL = new URL(newUrl);
                            return parsedProtocolURL.toString();
                        }
                        catch (MalformedURLException e2) {
                            System.err.println("[-] Could not parse URL " + urlToCondition + " by attempting to add a protocol.");
                            return null;
                        }
                    }
                    else {
                        // What if it just starts with the host and assumes the protocol?
                        try {
                            URL parsedProtocolURL = new URL(parsedBase.getProtocol() + "://" + urlToCondition);
                            return parsedProtocolURL.toString();
                        }
                        catch (MalformedURLException e2) {
                            System.err.println("[-] Could not parse URL " + urlToCondition + " by attempting to add a protocol.");
                            return null;
                        }
                    }
                }
            }
        }
        catch (MalformedURLException be){
            System.err.println("[-] Could not parse base URL " + baseUrl);
            return null;
        }
    }

    /**
     * Take the HTML this object has and find all of the scripts within it
     */
    private void getScriptsFromHtml(){
        Pattern pattern = Pattern.compile("<\\s*script[^>]*src=\"(.*?)\"[^>]*>(.*?)<\\s*/\\s*script>");
        Matcher matcher = pattern.matcher(html);
        while (matcher.find()) {
            String scriptSrc = conditionReceivedUrl(matcher.group(1), url);
            String scriptTag = matcher.group(0);
            JavascriptResource scriptObject = new JavascriptResource(myCallbacks, scriptSrc, scriptTag);
            htmlScriptData.put(scriptSrc, scriptObject);
            htmlScripts.add(scriptSrc);
        }
    }

    /**
     * Set the HTML for the page this object will evaluate
     * @param htmlString the string of the page's body, or HTML
     */
    public void setHtml(String htmlString){
        html = htmlString;
        // parse the html for scripts
        getScriptsFromHtml();
    }

    /**
     * Get the HTML being reviewed by this object
     * @return a string of the HTML being evaluated here
     */
    public String getHtml(){
        return html;
    }

    /**
     * Get a list of the URLs, as strings, of JavaScript resources referenced by this page in the HTML
     * @return a list of the URLs, as strings, of JavaScript resources referenced by this page in the HTML
     */
    public List<String> getHtmlScripts(){
        return htmlScripts;
    }

    /**
     * Get a list of the URLs, as strings, of JavaScript resources referenced by this page in DOM
     * @return a list of the URLs, as strings, of JavaScript resources referenced by this page in DOM
     */
    public List<String> getDomScripts(){
        return domScripts;
    }

    /**
     * Given a list of URLs to JS resources, return a list of resources which are cross-domain
     * @param inList a list of strings which are URLs to JS resources
     * @return       a list of strings which are URLs to cross-domain JS resources
     */
    private List<String> selectCrossDomainScripts(List<String> inList){
        List<String> returnList = new ArrayList<>();
        for (String thisScript : inList) {
            if (scriptIsCrossDomain(thisScript)) {
                returnList.add(thisScript);
            }
        }
        return returnList;
    }

    /**
     * Get a list of the cross-domain scripts referenced by the page's HTML
     * @return a List object of Strings which are URLs to JS resources referenced by the page's HTML
     */
    public List<String> getCrossDomainHtmlScripts(){
        // TODO - Add a test
        return selectCrossDomainScripts(htmlScripts);
    }

    /**
     * Get a list of the cross-domain scripts not referenced by the page's  DO
     * @return a List object of Strings which are URLs to cross-domain JS resources not referenced by the page's DOM
     */
    public List<String> getCrossDomainDomScripts(){
        // TODO - Add a test
        return selectCrossDomainScripts(domScripts);
    }

    /**
     * Get a list of the scripts in the HTML/DOM which are cross-domain
     * @return a List object of Strings which are URLs to JS resources in the HTML/DOM which are cross-domain
     */
    public List<String> getCrossDomainScripts(){
        // TODO - Add a test
        return selectCrossDomainScripts(getScripts());
    }

    /**
     * Get a list of the scripts not referenced by the page's HTML, but present in the DOM
     * @return a List object of Strings which are URLs to JS resources not referenced by the page's HTML, but present in the DOM
     */
    public List<String> getDomOnlyScripts(){
        // TODO - Add a test
        List<String> returnList = new ArrayList<>();
        for (String thisScript : domScripts){
            if (!htmlScripts.contains(thisScript)){
                returnList.add(thisScript);
            }
        }
        return returnList;
    }

    /**
     * Get a list of the cross-domain scripts not referenced by the page's HTML, but present in the DOM
     * @return a List object of Strings which are URLs to cross-domain JS resources not referenced by the page's HTML, but present in the DOM
     */
    public List<String> getDomOnlyCrossDomainScripts(){
        // TODO - Add a test
        return selectCrossDomainScripts(getDomOnlyScripts());
    }

    /**
     * Get a list of the scripts not referenced by the page's HTML and DOM
     * @return a List object of Strings which are URLs to cross-domain JS resources referenced by the page's HTML and DOM
     */
    public List<String> getScripts(){
        List<String> allScripts = new ArrayList<>();
        allScripts.addAll(htmlScripts);
        allScripts.addAll(domScripts);
        return allScripts;
    }

    /**
     * Get the JavascriptResource object from this finder for a given URL
     * @param scriptSrc the src attribute for a javascript resource referenced by this page/DOM
     * @return          the javascriptresource object for this item, null if the src string isn't found
     */
    public JavascriptResource getScriptObjectFor(String scriptSrc){
        if (htmlScripts.contains(scriptSrc)) {
            return htmlScriptData.get(scriptSrc);
        } 
        else {
            if (domScripts.contains(scriptSrc)) {
                return domScriptData.get(scriptSrc);
            } 
            else {
                return null;
            }
        }
    }

    /**
     * Get the HTML tag, as a string, from this finder for a given URL
     * @param scriptSrc the src attribute for a javascript resource referenced by this page/DOM
     * @return          the HTML tag, as a string, for this item, null if the src string isn't found
     */
    public String getHtmlTagFor(String scriptSrc){
        JavascriptResource resource = getScriptObjectFor(scriptSrc);
        if (resource != null) {
            return resource.getOriginalTag();
        }
        else {
            return null;
        }
    }

    /**
     * Is a given URL cross-domain to the page evaluated by this object?
     * @param scriptUrlToCheck the url, as a string, to check
     * @return                 true if it's cross-domain, false otherwise
     */
    public Boolean scriptIsCrossDomain(String scriptUrlToCheck){
        try {
            URL parsedUrlToCheck = new URL(scriptUrlToCheck);
            return !parsedUrlToCheck.getHost().equals(parsedUrl.getHost());
        }
        catch (Exception e) {
            System.err.println("[-] Could not parse the URL provided to scriptIsCrossDomain - " + scriptUrlToCheck);
            return false;
        }
    }
}
