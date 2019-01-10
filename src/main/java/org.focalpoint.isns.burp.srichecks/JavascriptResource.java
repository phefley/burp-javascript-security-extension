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

    public JavascriptResource(){
        
    }

    public JavascriptResource(IBurpExtenderCallbacks callbacks, String srcString, String tagString){
        setSrc(srcString);
        setOriginalTag(tagString);
        getResource(callbacks);
        calculateHashes();
    }

    public void setSrc(String newSrc){
        src = newSrc;
    }

    public String getSrc(){
        return src;
    }

    public void setOriginalTag(String ot){
        originalTag = ot;
        parseTag();
    }

    public String getOriginalTag(){
        return originalTag;
    }

    public void parseTag(){
        Document doc = Jsoup.parse(originalTag);
        parsedTag = doc.getElementsByTag("script").first();
    }

    public Element getParsedTag(){
        return parsedTag;
    }

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
            System.err.println("[FOPO-SRI][-] DNS did not resolve for the JavaScript resource at " + src);
        }

        if (dnsValid){
            try {
                Requester myRequester = new Requester(callbacks, src);
                data = myRequester.getResponseBody();
            }
            catch (Exception ex) {
                data = NO_DATA_RECEIVED;
                System.err.println("[FOPO-SRI][-] There was an issue getting the JavaScript file at " + src);
            }
        }
    }

    public boolean hasData(){
        return (!data.equals(NO_DATA_RECEIVED));
    }

    public boolean hasValidHostname(){
        return dnsValid;
    }

    private String dataHasher(String algorithm) {
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

    public void calculateHashes(){
        hashes.put("sha256",dataHasher("SHA-256"));
        hashes.put("sha384",dataHasher("SHA-384"));
        hashes.put("sha512",dataHasher("SHA-512"));
    }

    public HashMap<String,String> getHashes(){
        return hashes;
    }

    public Boolean checkHash(String hashValue, String algorithm){
        if (hashes.keySet().contains(algorithm))
        {
            return (hashes.get(algorithm).equals(hashValue));
        }
        else {
            return false;
        }
    }

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
