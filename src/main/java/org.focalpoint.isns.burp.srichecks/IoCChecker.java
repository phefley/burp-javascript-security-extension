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

    /**
     * Constructor for IoCCheckers.
     */
    public IoCChecker(){
        //addIoc(new JavaScriptIOC("Annex Cloud Investigation Report 8/3/18","http://cdn.socialannex.com/s13/s13_ac_mc.js"));
        //addIoc(new JavaScriptIOC("Annex Cloud Investigation Report 8/3/18","http://cdn.socialannex.com/c/js/json3.js"));
        //addIoc(new JavaScriptIOC("Annex Cloud Investigation Report 8/3/18","https://cdn.socialannex.com/s13/s13_ac_mc.js"));
        //addIoc(new JavaScriptIOC("Annex Cloud Investigation Report 8/3/18","https://cdn.socialannex.com/c/js/json3.js"));
    }

    /**
     * Add a new indicator of compromise (IOC) object to this checker
     * @param  newIoc  The new IOC object to add,
     */
    public void addIoc(JavaScriptIOC newIoc){
        iocs.add(newIoc);
    }

    /**
     * Check to see if a given URL is a hit on any known intel
     * @param  url  The string of the URL to check.
     * @return      Returns true if this is a hit and false if it does not match any known IOCs.
     */
    public boolean checkUrl(String url){
        for (JavaScriptIOC thisIoc : iocs){
            if (thisIoc.getUrl().equals(url)){
                return true;
            }
        }
        return false;
    }

    /**
     * Check to see if a given hash/algorithm set is a hit on any known intel
     * @param  algorithm  The string of the algorithm to check.
     * @param  hashValue  The base64 encoded hash value to check.
     * @return      Returns true if this is a hit and false if it does not match any known IOCs.
     */
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

    /**
     * Check a set of hashes available against all known intel.
     * @param  hashLookup  A hashmap keyed by algorithm where the values are Base64 encoded hashes
     * @return             Returns true if this is a hit and false if it does not match any known IOCs.
     */
    public boolean checkHashes(HashMap<String,String> hashLookup){
        for (String algo : hashLookup.keySet()){
            if (checkHash(algo, hashLookup.get(algo))){
                return true;
            }
        }
        return false;
    }

    /**
     * Check a set of hashes available against all known intel and return the source for the first hit.
     * @param  hashLookup  A hashmap keyed by algorithm where the values are Base64 encoded hashes
     * @return             Returns a string which was the source of the intel.
     */
    public String getHashesSource(HashMap<String,String> hashLookup){
        for (String algo : hashLookup.keySet()){
            if (checkHash(algo, hashLookup.get(algo))){
                return getHashSource(algo, hashLookup.get(algo));
            }
        }
        return null;
    }

    /**
     * Check to see if a given hash/algorithm set is a hit on any known intel and return the first source.
     * @param  algorithm  The string of the algorithm to check.
     * @param  hashValue  The base64 encoded hash value to check.
     * @return            Returns a string which was the source of the intel.
     */    
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

    /**
     * Check to see if a URL is a hit on any known intel and return the first source.
     * @param  url  The string of the URL to check.
     * @return      Returns a string which was the source of the intel.
     */
    public String getUrlSource(String url){
        for (JavaScriptIOC thisIoc : iocs){
            if (thisIoc.getUrl().equals(url)){
                return thisIoc.getSource();
            }
        }
        return null;
    }

    /**
     * Import IOCs from a JSON file
     * @param  fileName  the path to the JSON file to import.
     */
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

    /**
     * Get the number of IOCs in this checker
     * @return  the Integer count of IOCs
     */
    public Integer getIocCount(){
        return iocs.size();
    }
}