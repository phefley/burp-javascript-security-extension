package org.focalpoint.isns.burp.srichecks;

import org.focalpoint.isns.burp.srichecks.JavascriptResource;
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

// This is for JDK 11
/*
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
*/

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

    public void setUrl(String urlString){
        url = urlString;
        try {
            parsedUrl = new URL(urlString);
        }
        catch (Exception e) {
            System.err.println("[-] Could not parse URL: " + urlString);
        }
    }

    public String getUrl(){
        return url;
    }

    public void setTimeout(Integer timeoutInSeconds){
        PAGE_WAIT_TIMEOUT = timeoutInSeconds;
    }

    public Integer getTimeout(){
        return PAGE_WAIT_TIMEOUT;
    }

    public void setDriverPath(String driverPathStr){
        driverPath = driverPathStr;
    }

    public String getDriverPath(){
        return driverPath;
    }

    public void retrieveHtml(){
        if (!url.equals("NONE")){
            // TODO - download the HTML via the burp extender HTTP interface
            // TODO - what about proxies? You may need to account for proxies if not using the burp HTTP library
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
                        domScriptData.put(src, new JavascriptResource(src, scriptTag));
                    }
                }
            }
            catch (StaleElementReferenceException e){
                System.err.println("[" + url + "][-] - Error attempting to access a script tag on this item which is no longer in the driver DOM.");
            }
        }
        stopDriver();
    }

    public void stopDriver(){
        driver.close();
        driver.quit();
    }

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

    private void getScriptsFromHtml(){
        Pattern pattern = Pattern.compile("<\\s*script[^>]*src=\"(.*?)\"[^>]*>(.*?)<\\s*/\\s*script>");
        Matcher matcher = pattern.matcher(html);
        while (matcher.find()) {
            String scriptSrc = conditionReceivedUrl(matcher.group(1), url);
            String scriptTag = matcher.group(0);
            JavascriptResource scriptObject = new JavascriptResource(scriptSrc, scriptTag);
            htmlScriptData.put(scriptSrc, scriptObject);
            htmlScripts.add(scriptSrc);
        }
    }

    public void setHtml(String htmlString){
        html = htmlString;
        // parse the html for scripts
        getScriptsFromHtml();
    }

    public String getHtml(){
        return html;
    }

    public List<String> getHtmlScripts(){
        return htmlScripts;
    }

    public List<String> getDomScripts(){
        return domScripts;
    }

    private List<String> selectCrossDomainScripts(List<String> inList){
        List<String> returnList = new ArrayList<>();
        for (String thisScript : inList) {
            if (scriptIsCrossDomain(thisScript)) {
                returnList.add(thisScript);
            }
        }
        return returnList;
    }

    public List<String> getCrossDomainHtmlScripts(){
        // TODO - Add a test
        return selectCrossDomainScripts(htmlScripts);
    }

    public List<String> getCrossDomainDomScripts(){
        // TODO - Add a test
        return selectCrossDomainScripts(domScripts);
    }

    public List<String> getCrossDomainScripts(){
        // TODO - Add a test
        return selectCrossDomainScripts(getScripts());
    }

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

    public List<String> getDomOnlyCrossDomainScripts(){
        // TODO - Add a test
        return selectCrossDomainScripts(getDomOnlyScripts());
    }

    public List<String> getScripts(){
        List<String> allScripts = new ArrayList<>();
        allScripts.addAll(htmlScripts);
        allScripts.addAll(domScripts);
        return allScripts;
    }

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

    public String getHtmlTagFor(String scriptSrc){
        JavascriptResource resource = getScriptObjectFor(scriptSrc);
        if (resource != null) {
            return resource.getOriginalTag();
        }
        else {
            return null;
        }
    }

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
