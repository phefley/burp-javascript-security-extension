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


    /**
     * Constructor when you have a source only
     * @param  sourceString  The source for the IOC.
     */
    public JavaScriptIOC(String sourceString){
        setSource(sourceString);
    }

    /**
     * Constructor when you have a source and a URL
     * @param  sourceString  The source for the IOC.
     * @param  urlString     The string which is the URL IOC.
     */
    public JavaScriptIOC(String sourceString, String urlString){
        setSource(sourceString);
        setUrl(urlString);
    }

    /** 
     * Default constructor
     */
    public JavaScriptIOC(){}

    /**
     * Constructor when you have a source, URL, and a hash set
     * @param  sourceString  The source for the IOC.
     * @param  urlString     The string which is the URL IOC.
     * @param  hashes        A hashmap keyed by algorithm name of base64 encoded hash values.
     */
    public JavaScriptIOC(String sourceString, String urlString, HashMap<String,String> hashes){
        hashLookup = hashes;
        setSource(sourceString);
        setUrl(urlString);
    }

    /**
     * Constructor when you have a JSONObject, which is used to import from a file.
     * @param  jsonIoc  A JSONObject to use from a file import to make a new IOC
     */
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

    /**
     * Set the URL for this IOC
     * @param  urlString  The URL to set on this IOC
     */
    public void setUrl(String urlString){
        url = urlString;
    }

    /** 
     * Get the URL referenced by this IOC
     * @return  the URL IOC. An empty string ("") if not set.
     */
    public String getUrl(){
        return url;
    }

    /**
     * Set the source for this IOC
     * @param  sourceString  The source to set on this IOC
     */
    public void setSource(String sourceString){
        source = sourceString;
    }

    /** 
     * Get the source referenced by this IOC
     * @return  the IOC source. An empty string ("") if not set.
     */    
    public String getSource(){
        return source;
    }

    /** 
     * Add a hash IOC to this object
     * @param  algorithmStr  a String of the algorithm. Must be in "md5", "sha1", "sha256", "sha384", "sha512"
     * @param  hashStr       the base64 encoded hash
     */
    public void addHash(String algorithmStr, String hashStr){
        if (VALID_ALGORITHMS.contains(algorithmStr)){
            hashLookup.put(algorithmStr, hashStr);
        }
    }

    /** 
     * Does this object have a hash for a given algorithm?
     * @param  algorithm  a string of the algorithm name
     * @return            true if it has a has for that algorithm, false otherwise
     */
    public Boolean hasHash(String algorithm){
        return hashLookup.containsKey(algorithm);
    }

    /**
     * Get the hash value for any given algorithm
     * @param  algorithmStr  The algorithm to get the hash for
     * @return               The base64 encoded hash value or null if it doesn't have that hash
     */
    public String getHash(String algorithmStr){
        if (hasHash(algorithmStr)){
            return hashLookup.get(algorithmStr);
        }
        else {
            return null;
        }
    }

    /**
     * Does this object equal another? This is needed for set management.
     * @param  obj  The object to test for equality to this instance
     * @return      True if reasonably equal, false if not equal
     */
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

    /**
     * Make a string out of this for internal use
     * @return a string representation of this object
     */
    private String stringify(){
        String outstr = "";
        outstr += source + "|";
        outstr += url + "|";
        outstr += hashLookup.toString();
        return outstr;
    }

    /**
     * Generate a hashcode (integer) unique to this object. Needed for set management.
     *   String representation --> MD5 --> bytes --> integer
     * @return unique integer hashcode for this object.
     */
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