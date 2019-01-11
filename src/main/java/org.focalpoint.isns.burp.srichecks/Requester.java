
package org.focalpoint.isns.burp.srichecks;

import java.net.URL;
import java.net.MalformedURLException;

import burp.IHttpService;
import burp.IExtensionHelpers;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IResponseInfo;
import java.util.Arrays;

public class Requester {
    private IHttpService burpHttpService;
    private String urlString;
    private URL urlObj;
    private IHttpRequestResponse rr;
    private IExtensionHelpers myHelpers;
    private IBurpExtenderCallbacks myCallbacks;
    private short statusCode = 0;
    private String responseBody = "";
    public static final String NO_DATA_RECEIVED = "NO DATA NO DATA NO DATA";

    public Requester(IBurpExtenderCallbacks callbacks, String url){
        setCallbacks(callbacks);
        setUrl(url);
        makeService();
        makeRequest();
    }

    public void setUrl(String url){
        urlString = url;
        try {
            urlObj = new URL(url);
            makeService();
        }
        catch (MalformedURLException exception){
            System.err.println("[FOPO-SRI][-] Could not parse URL " + url);
        }
    }

    public void setCallbacks(IBurpExtenderCallbacks callbacks){
        myCallbacks = callbacks;
        myHelpers = myCallbacks.getHelpers();
    }

    public void makeService(){
        Boolean useHttps = (urlObj.getProtocol().equals("https"));
        int port = 0;
        if (urlObj.getPort() == -1){
            if (urlObj.getProtocol().equals("https")){
                port = 443;
            }
            if (urlObj.getProtocol().equals("http")){
                port = 80;
            }
        }
        else {
            port = urlObj.getPort();
        }
        burpHttpService = myHelpers.buildHttpService(urlObj.getHost(), port, useHttps);
    }

    public void makeRequest(){
        byte[] requestBytes = myHelpers.buildHttpRequest(urlObj);
        rr = myCallbacks.makeHttpRequest(burpHttpService, requestBytes);
        IResponseInfo responseObj = myHelpers.analyzeResponse(rr.getResponse());
        statusCode = responseObj.getStatusCode();
        if (statusCode == 200){
            byte[] responseBodyBytes = Arrays.copyOfRange(rr.getResponse(), responseObj.getBodyOffset(), rr.getResponse().length);
            responseBody = myHelpers.bytesToString(responseBodyBytes);
        }
        else {
            responseBody = NO_DATA_RECEIVED;
        }
    }

    public short getStatusCode(){
        return statusCode;
    }

    public String getResponseBody(){
        return responseBody;
    }

}