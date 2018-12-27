package org.focalpoint.isns.burp.srichecks;

import java.util.HashMap;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

// The following is for JDK 11
// import java.net.http.HttpClient;
// import java.net.http.HttpRequest;
// import java.net.http.HttpResponse;
// import java.net.http.HttpResponse.BodyHandlers;
import jdk.incubator.http.HttpClient;
import jdk.incubator.http.HttpRequest;
import jdk.incubator.http.HttpResponse;
import jdk.incubator.http.HttpResponse.BodyHandler;


import java.net.URI;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class JavascriptResource {
    private String src;
    private String originalTag;
    private Element parsedTag;
    private String data = "";
    private HashMap<String,String> hashes = new HashMap<String,String>();

    public JavascriptResource(){
        
    }

    public JavascriptResource(String srcString, String tagString){
        setSrc(srcString);
        setOriginalTag(tagString);
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

    public void getResource(){
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(src))
            .build();
        try {
            HttpResponse<String> response = client.send(request, BodyHandler.asString());
            data = response.body();
        }
        catch (Exception ex) {
            System.err.println("[-] There was an issue getting the JavaScript file at " + src);
        }
    }

    public boolean hasData(){
        return (!data.equals(""));
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
