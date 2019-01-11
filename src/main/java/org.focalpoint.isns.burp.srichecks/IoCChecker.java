
package org.focalpoint.isns.burp.srichecks;

import java.util.HashSet;
import java.util.HashMap;

// File I/O
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;

// JSON Handling
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import org.focalpoint.isns.burp.srichecks.JavaScriptIOC;

public class IoCChecker {
    private HashSet<JavaScriptIOC> iocs = new HashSet<JavaScriptIOC>();

    public IoCChecker(){
        // TODO This is from a list of known, bad URLs. This should be improved.
        addIoc(new JavaScriptIOC("Annex Cloud Investigation Report 8/3/18","http://cdn.socialannex.com/s13/s13_ac_mc.js"));
        addIoc(new JavaScriptIOC("Annex Cloud Investigation Report 8/3/18","http://cdn.socialannex.com/c/js/json3.js"));
        addIoc(new JavaScriptIOC("Annex Cloud Investigation Report 8/3/18","https://cdn.socialannex.com/s13/s13_ac_mc.js"));
        addIoc(new JavaScriptIOC("Annex Cloud Investigation Report 8/3/18","https://cdn.socialannex.com/c/js/json3.js"));
    }

    public void addIoc(JavaScriptIOC newIoc){
        iocs.add(newIoc);
    }

    public boolean checkUrl(String url){
        for (JavaScriptIOC thisIoc : iocs){
            if (thisIoc.getUrl().equals(url)){
                return true;
            }
        }
        return false;
    }

    public boolean checkHash(String algorithm, String hashValue){
        for (JavaScriptIOC thisIoc : iocs){
            if (thisIoc.hasHash(algorithm)){
                if (thisIoc.getHash(algorithm).equals(hashValue)){
                    return true;
                }
            }
        }
        return false;
    }

    public boolean checkHashes(HashMap<String,String> hashLookup){
        for (String algo : hashLookup.keySet()){
            if (checkHash(algo, hashLookup.get(algo))){
                return true;
            }
        }
        return false;
    }

    public String getHashesSource(HashMap<String,String> hashLookup){
        for (String algo : hashLookup.keySet()){
            if (checkHash(algo, hashLookup.get(algo))){
                return getHashSource(algo, hashLookup.get(algo));
            }
        }
        return null;
    }

    public String getHashSource(String algorithm, String hashValue){
        for (JavaScriptIOC thisIoc : iocs){
            if (thisIoc.hasHash(algorithm)){
                if (thisIoc.getHash(algorithm).equals(hashValue)){
                    return thisIoc.getSource();
                }
            }
        }
        return null;
    }

    public String getUrlSource(String url){
        for (JavaScriptIOC thisIoc : iocs){
            if (thisIoc.getUrl().equals(url)){
                return thisIoc.getSource();
            }
        }
        return null;
    }

    public void importIocsFromJson(String fileName){
        JSONParser parser = new JSONParser();
        try {
            JSONArray array = (JSONArray) parser.parse(new FileReader(fileName));
            for (Object obj : array){
                JSONObject iocJson = (JSONObject) obj;
                JavaScriptIOC newIoc = new JavaScriptIOC(iocJson);
                addIoc(newIoc);
            }
        } catch (FileNotFoundException e) {
            System.err.println("[FOPO-SRI][IOC-Import][-] File at " + fileName + " not found.");
            e.printStackTrace();
        } catch (IOException e) {
            System.err.println("[FOPO-SRI][IOC-Import][-] IO exception for file " + fileName + ".");
            e.printStackTrace();
        } catch (ParseException e) {
            System.err.println("[FOPO-SRI][IOC-Import][-] Parser exception for file " + fileName + ".");
            e.printStackTrace();
        }
    }

    public Integer getIocCount(){
        return iocs.size();
    }
}