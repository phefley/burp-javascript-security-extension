
package org.focalpoint.isns.burp.srichecks;

import java.util.List;
import java.util.ArrayList;
import java.util.HashMap;
import org.focalpoint.isns.burp.srichecks.JavaScriptIOC;

public class IoCChecker {
    private List<JavaScriptIOC> iocs = new ArrayList<>();

    public IoCChecker(){
        // TODO This is from a list of known, bad URLs. This should be improved.
        iocs.add(new JavaScriptIOC("Annex Cloud Investigation Report 8/3/18","http://cdn.socialannex.com/s13/s13_ac_mc.js"));
        iocs.add(new JavaScriptIOC("Annex Cloud Investigation Report 8/3/18","http://cdn.socialannex.com/c/js/json3.js"));
        iocs.add(new JavaScriptIOC("Annex Cloud Investigation Report 8/3/18","https://cdn.socialannex.com/s13/s13_ac_mc.js"));
        iocs.add(new JavaScriptIOC("Annex Cloud Investigation Report 8/3/18","https://cdn.socialannex.com/c/js/json3.js"));
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
}