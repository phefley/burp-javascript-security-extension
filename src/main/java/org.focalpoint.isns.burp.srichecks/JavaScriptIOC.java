
package org.focalpoint.isns.burp.srichecks;

import java.util.HashMap;
import java.util.List;
import java.util.Arrays;

import org.json.simple.JSONObject;
import org.json.simple.JSONArray;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;

import java.nio.ByteBuffer;


public class JavaScriptIOC {
    private String url = "";
    private String source = "";
    private HashMap<String,String> hashLookup = new HashMap<String,String>();
    public static List<String> VALID_ALGORITHMS = Arrays.asList("md5", "sha1", "sha256", "sha384", "sha512");

    
    public JavaScriptIOC(String sourceString){
        setSource(sourceString);
    }

    public JavaScriptIOC(String sourceString, String urlString){
        setSource(sourceString);
        setUrl(urlString);
    }

    public JavaScriptIOC(){}

    public JavaScriptIOC(String sourceString, String urlString, HashMap<String,String> hashes){
        hashLookup = hashes;
        setSource(sourceString);
        setUrl(urlString);
    }

    public JavaScriptIOC(JSONObject jsonIoc){
        setSource((String) jsonIoc.get("source"));
        if (jsonIoc.containsKey("url")){
            setUrl((String) jsonIoc.get("url"));
        }
        if (jsonIoc.containsKey("hashes")){
            JSONObject hashes = (JSONObject) jsonIoc.get("hashes");
            for (String algo : VALID_ALGORITHMS){
                if (hashes.containsKey(algo)){
                    addHash(algo, (String) hashes.get(algo));
                }
            }
        }
    }

    public void setUrl(String urlString){
        url = urlString;
    }

    public String getUrl(){
        return url;
    }

    public void setSource(String sourceString){
        source = sourceString;
    }

    public String getSource(){
        return source;
    }

    public void addHash(String algorithmStr, String hashStr){
        if (VALID_ALGORITHMS.contains(algorithmStr)){
            hashLookup.put(algorithmStr, hashStr);
        }
    }
    
    public Boolean hasHash(String algorithm){
        return hashLookup.containsKey(algorithm);
    }

    public String getHash(String algorithmStr){
        if (hasHash(algorithmStr)){
            return hashLookup.get(algorithmStr);
        }
        else {
            return null;
        }
    }

    public boolean equals(Object obj){
        if (!(obj instanceof JavaScriptIOC)){
            return false;
        }
        if (obj == this){
            return true;
        }
        JavaScriptIOC jsObj = (JavaScriptIOC) obj;
        if (!(jsObj.getSource().equals(source))){
            return false;
        }
        if (!(jsObj.getUrl().equals(url))){
            return false;
        }
        for (String algo : hashLookup.keySet()){
            if (!(jsObj.hasHash(algo))){
                return false;
            }
            else {
                if (!(jsObj.getHash(algo).equals(getHash(algo)))){
                    return false;
                }
            }
        }
        return true;
    }

    private String stringify(){
        String outstr = "";
        outstr += source + "|";
        outstr += url + "|";
        outstr += hashLookup.toString();
        return outstr;
    }

    public int hashCode(){
        // Make a unique int for each object
        String algorithm = "MD5";
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            byte[] encodedHash = digest.digest(stringify().getBytes(StandardCharsets.UTF_8));
            return ByteBuffer.wrap(encodedHash).getInt();
        }
        catch (NoSuchAlgorithmException ex) {
            System.err.println("[-] The provided algorithm string (" + algorithm + ") is not valid.");
            return -1;
        }
    }
}