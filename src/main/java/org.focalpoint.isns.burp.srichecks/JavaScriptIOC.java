
package org.focalpoint.isns.burp.srichecks;

import java.util.HashMap;

public class JavaScriptIOC {
    private String url;
    private String source;
    private HashMap<String,String> hashLookup = new HashMap<String,String>();

    
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
        hashLookup.put(algorithmStr, hashStr);
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
}