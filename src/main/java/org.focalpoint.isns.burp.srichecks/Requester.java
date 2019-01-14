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

    /**
     * Public constructor for Requester objects
     * @param   callbacks  the burp suite callbacks object
     * @param   url        a String containing the URL you'll want to request
     * @return             a new Requestor object
     */
    public Requester(IBurpExtenderCallbacks callbacks, String url){
        setCallbacks(callbacks);
        setUrl(url);
        makeService();
        makeRequest();
    }

    /**
     * Set the URL which the requestor will pull
     * @param  url  a String of the URL to obtain
     */
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

    /**
     * Set the callbacks object to link back to burp suite
     * @param  callbacks  the callbacks object provided to the burp extension
     */
    public void setCallbacks(IBurpExtenderCallbacks callbacks){
        myCallbacks = callbacks;
        myHelpers = myCallbacks.getHelpers();
    }


    /**
     * Generate the HTTP service required to use the Burp HTTP interface
     */
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

    /** 
     * Make the HTTP request this object is set up for
     */
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

    /**
     * Get the HTTP status code that was provided
     * @return  HTTP status code as a short
     */
    public short getStatusCode(){
        return statusCode;
    }

    /**
     * Get the response body from the request
     * @return  the HTTP response body as a String
     */
    public String getResponseBody(){
        return responseBody;
    }

}