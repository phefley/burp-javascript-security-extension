/**
 * BurpSuite JavaScript Security Extension
 * Copyright (C) 2019  Focal Point Data Risk, LLC
 * Written by: Peter Hefley
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

import org.openqa.selenium.Cookie;

import org.openqa.selenium.chrome.ChromeDriverService;
import org.openqa.selenium.remote.RemoteWebDriver;
import java.io.File;
import java.io.IOException;
import java.io.FileOutputStream;
import java.io.InputStream;

import java.util.concurrent.TimeUnit;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import java.util.List;
import java.net.URL;
import java.net.URI;
import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;

public class ScriptFinder{
    private IBurpExtenderCallbacks myCallbacks;
    private Integer PAGE_WAIT_TIMEOUT = 10;
    private String url="NONE";
    private String html="NONE";
    private List<String> requestHeaders = new ArrayList<>();
    private List<String> domScripts = new ArrayList<>();
    private List<String> htmlScripts = new ArrayList<>();
    // Something to store a parsed URL
    private URL parsedUrl;
    // A webdriver service manager to handle the life and death of the driver objects
    private DriverServiceManager serviceManager = null;
    // A webdriver object
    private WebDriver driver;
    // A dictionary of dom and html script data, respectively
    private HashMap<String,JavascriptResource> domScriptData = new HashMap<String,JavascriptResource>();
    private HashMap<String,JavascriptResource> htmlScriptData = new HashMap<String,JavascriptResource>();



    public ScriptFinder(){
    }

    /**
     * Set the driver service manager to use for this finder
     * @param sm the driver service manager to use
     */
    public void setDriverManager(DriverServiceManager sm){
        serviceManager = sm;
    }

    /**
     * Get rge driver service manager used by this instance
     * @return the driverservicemanager object being used by this object
     */
    public DriverServiceManager getDriverManager(){
        return serviceManager;
    }

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
     * Set the request headers
     * @param headers - a list of request headers
     */
    public void setRequestHeaders(List<String> headers){
        requestHeaders = new ArrayList<>();
        requestHeaders.addAll(headers);
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
                HttpResponse<String> response = client.send(request, BodyHandlers.ofString());
                setHtml(response.body());
            }
            catch (Exception ex) {
                System.err.println("[-] There was an issue getting the JavaScript file at " + url);
                System.err.println(ex.toString());
                ex.printStackTrace();
            }
        }
    }

    /**
     * Start the Selenium chrome driver instance with lean options
     */
    public void startDriver(){
        if (serviceManager != null){
            ChromeOptions options = new ChromeOptions();
            options.addArguments("--headless");
            options.addArguments("--no-sandbox");
            options.addArguments("--disable-dev-shm-usage");
            HashMap<String, Object> prefs = new HashMap<String, Object>(); 
            prefs.put("profile.managed_default_content_settings.images", 2);
            options.setExperimentalOption("prefs", prefs); 

            driver = new RemoteWebDriver(serviceManager.getService().getUrl(), options);
            driver.manage().timeouts().implicitlyWait(PAGE_WAIT_TIMEOUT, TimeUnit.SECONDS); // Wait for the page to be completely loaded. Or reasonably loaded.
        }
        else {
            System.err.println("[JS-SRI][-] You must set a driver service manager before you can start a driver.");
        }
    }

    /**
     * sets the driver's cookies up based on the requestHeaders set
     */
    private void setDriverCookies(){
        // You can't set cookies until you have the domain set in the DOM, this is a fix for that
        try {
            driver.get(url);
        }
        catch (TimeoutException e){
            System.err.println("[" + url + "][-] - timeout when connecting.");
        }

        // Set the driver's cookies based on the headers, if there are any
        if (requestHeaders != null){
            for (String header: requestHeaders){
                if (header.startsWith("Cookie: ")){
                    // This is a cookie header, split it up
                    String cookieString = header.substring(8,header.length());
                    for (String kvPair : cookieString.split(";")){
                        String key = kvPair.split("=")[0].trim();
                        String value = kvPair.split("=")[1].trim();
                        Cookie cookieObj = new Cookie(key, value);
                        try {
                            driver.manage().addCookie(cookieObj);
                        }
                        catch (org.openqa.selenium.UnableToSetCookieException d){
                            System.err.println("[JS-SRI][-] Could not set cookie for key " + key + " and value " + value);
                        }
                    }
                }
            }
        }
    }


    /**
     * Load the DOM and check for any referenced scripts
     * Starts and stops the selenium instance
     */
    public void checkForDomScripts(){
        startDriver();

        setDriverCookies();

        // Now actually get the page
        try {
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
        if (driver != null){
            driver.close();
            driver.quit();
        }
    }

    /**
     * Condition a URL to get the full protocol, FQDN, and path from any given URL with respect to the base URL
     * @param urlToCondition the URL to condition to it's full glory
     * @param baseUrl        the base URL to reference for protocol and FQDN as needed
     * @return               the full URL reconstructed as a string
     */
    public String conditionReceivedUrl(String urlToCondition, String baseUrl){
        try {
            URL parsedBase = new URL(baseUrl);
            try {
                URL relativeUrl = new URL(parsedBase, urlToCondition);
                return relativeUrl.toString();
            }
            catch (MalformedURLException e) {
                System.err.println("[-] Could not parse URL " + urlToCondition);
                return null;
            }
        }
        catch (MalformedURLException e){
            System.err.println("[-] Could not parse base URL " + baseUrl);
            return null;
        }
    }
    

    /**
     * Take the HTML this object has and find all of the scripts within it
     */
    private void getScriptsFromHtml(){
        Document doc = Jsoup.parse(html);
        for (Element jsElement : doc.getElementsByTag("script")){
            if (jsElement.hasAttr("src")){
                String scriptSrc = conditionReceivedUrl(jsElement.attr("src"), url);
                String scriptTag = jsElement.outerHtml();
                JavascriptResource scriptObject = new JavascriptResource(myCallbacks, scriptSrc, scriptTag);
                htmlScriptData.put(scriptSrc, scriptObject);
                htmlScripts.add(scriptSrc);
            }
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
        return selectCrossDomainScripts(htmlScripts);
    }

    /**
     * Get a list of the cross-domain scripts referenced by the page's  DOM
     * @return a List object of Strings which are URLs to cross-domain JS resources referenced by the page's DOM
     */
    public List<String> getCrossDomainDomScripts(){
        return selectCrossDomainScripts(domScripts);
    }

    /**
     * Get a list of the cross-domain scripts only referenced by the page's  DOM
     * @return a List object of Strings which are URLs to cross-domain JS resources only referenced by the page's DOM
     */
    public List<String> getCrossDomainDomOnlyScripts(){
        return selectCrossDomainScripts(getDomOnlyScripts());
    }

    /**
     * Get a list of the scripts in the HTML/DOM which are cross-domain
     * @return a List object of Strings which are URLs to JS resources in the HTML/DOM which are cross-domain
     */
    public List<String> getCrossDomainScripts(){
        return selectCrossDomainScripts(getScripts());
    }

    /**
     * Get a list of the scripts not referenced by the page's HTML, but present in the DOM
     * @return a List object of Strings which are URLs to JS resources not referenced by the page's HTML, but present in the DOM
     */
    public List<String> getDomOnlyScripts(){
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
