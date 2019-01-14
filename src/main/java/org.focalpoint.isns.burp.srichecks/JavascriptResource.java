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

import java.util.HashMap;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import org.focalpoint.isns.burp.srichecks.Requester;

import burp.IBurpExtenderCallbacks;

import java.net.URI;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

// For DNS checks
import java.net.InetAddress;
import java.net.UnknownHostException;

public class JavascriptResource {
    private String src;
    private String originalTag;
    private Element parsedTag;
    private String data = "";
    private Boolean dnsValid = false;
    public static final String NO_DATA_RECEIVED = "NO DATA NO DATA NO DATA";
    private HashMap<String,String> hashes = new HashMap<String,String>();

    /**
     * Default constructor
     */
    public JavascriptResource(){}

    /**
     * Constructor to use when you have all of the necessary items
     * @param  callbacks  The burp suite callbacks object, needed to use the HTTP interface
     * @param  srcString  The SRC attribute, or source, of the JavaScript resource
     * @param  tagString  A string of the HTML tag which was used to reference the JavaScript
     */
    public JavascriptResource(IBurpExtenderCallbacks callbacks, String srcString, String tagString){
        setSrc(srcString);
        setOriginalTag(tagString);
        getResource(callbacks);
        calculateHashes();
    }

    /**
     * Set the source, or SRC attribute, of the object
     * @param newSrc A string containing the value of the SRC attribute for a JavaScript resource
     */
    public void setSrc(String newSrc){
        src = newSrc;
    }

    /**
     * Get the SRC for this object
     * @return a String of the SRC attribute for this JavaScript resource
     */
    public String getSrc(){
        return src;
    }

    /**
     * Set the original tag on this object, e.g., <script src="someurl"></script>
     * @param ot the string of the original HTML tag
     */
    public void setOriginalTag(String ot){
        originalTag = ot;
        parseTag();
    }

    /**
     * Get the original HTML tag
     * @return a string of the original HTML tag for this resource
     */
    public String getOriginalTag(){
        return originalTag;
    }

    /**
     * Parse the HTML tag that we have in to it's disparate parts, stored as a separate object.
     * Obtained using getParsedTag
     */
    public void parseTag(){
        Document doc = Jsoup.parse(originalTag);
        parsedTag = doc.getElementsByTag("script").first();
    }

    /** 
     * Get the parsedTag object
     * @return a jsoup Element object which is the original tag, all parsed out
     */
    public Element getParsedTag(){
        return parsedTag;
    }

    /**
     * Actually go and get the referenced JavaScript resource via HTTP through burp
     * @param callbacks the burp suite callbacks object, needed to use the burp suite HTTP interface
     */
    public void getResource(IBurpExtenderCallbacks callbacks){
        URI thisUri = URI.create(src);
        // Let's see if the DNS for the resource resolves
        InetAddress inetAddress;
        try {
            inetAddress = InetAddress.getByName(thisUri.getHost());
            dnsValid = true;
        }
        catch (UnknownHostException exception){
            dnsValid = false;
            data = NO_DATA_RECEIVED;
            System.err.println("[JS-SRI][-] DNS did not resolve for the JavaScript resource at " + src);
        }

        if (dnsValid){
            try {
                Requester myRequester = new Requester(callbacks, src);
                data = myRequester.getResponseBody();
            }
            catch (Exception ex) {
                data = NO_DATA_RECEIVED;
                System.err.println("[JS-SRI][-] There was an issue getting the JavaScript file at " + src);
            }
        }
    }

    /**
     * Does this resource have any data (the actual JavaScript file) that has been retrieved?
     * @return true if there is data present, false if not
     */
    public boolean hasData(){
        return (!data.equals(NO_DATA_RECEIVED));
    }

    /**
     * Determine if the FQDN for the source URL could be looked up
     * @return true if the DNS hostname could be looked up, false if not
     */
    public boolean hasValidHostname(){
        return dnsValid;
    }

    /**
     * Hash the data we have and store the hashes
     * @param  algorithm  the Java MessageDigest algorithm to use to generate the hash
     * @return            a base64 encoded representation of the hash value
     */
    private String dataHasher(String algorithm) {
        if (hasData()){
            try {
                MessageDigest digest = MessageDigest.getInstance(algorithm);
                byte[] encodedHash = digest.digest(data.getBytes(StandardCharsets.UTF_8));
                return Base64.getEncoder().encodeToString(encodedHash);
            }
            catch (NoSuchAlgorithmException ex) {
                System.err.println("[-] The provided algorithm string (" + algorithm + ") is not valid.");
                return "";
            }
        }
    }

    /**
     * Calculate all of the hashes for all valid algorithms for this item
     */
    public void calculateHashes(){
        if (hasData()){
            hashes.put("sha256",dataHasher("SHA-256"));
            hashes.put("sha384",dataHasher("SHA-384"));
            hashes.put("sha512",dataHasher("SHA-512"));
            hashes.put("md5",dataHasher("MD5"));
            hashes.put("sha1",dataHasher("SHA-1"));
        }
    }

    /**
     * Get the hashes for this object
     * @return a hashmap keyed by algorithm of all base64 encoded hashes for this object's data
     */
    public HashMap<String,String> getHashes(){
        return hashes;
    }

    /** 
     * Check to see if a given algorithm/hash value pair is a match for this object
     * @param  hashValue  the base64 encoded hash value to chec
     * @param  algorithm  the string name of the algorithm for this hash
     * @return            true if the given algorithm/hash value pair is a match for this resource
     */
    public Boolean checkHash(String hashValue, String algorithm){
        if (hashes.keySet().contains(algorithm))
        {
            return (hashes.get(algorithm).equals(hashValue));
        }
        else {
            return false;
        }
    }

    /**
     * Check the SRI integrity of a javascript tag
     * @return true if the integrity attribute is correct, false otherwise
     */
    public Boolean checkIntegrity(){
        if (parsedTag.hasAttr("integrity")) {
            String integrityAttribute = parsedTag.attr("integrity");
            String algorithm = integrityAttribute.substring(0, integrityAttribute.indexOf("-"));
            String hashToCheck = integrityAttribute.substring(integrityAttribute.indexOf("-")+1);
            return checkHash(hashToCheck, algorithm);
        } else {
            return false;
        }
    }
}
