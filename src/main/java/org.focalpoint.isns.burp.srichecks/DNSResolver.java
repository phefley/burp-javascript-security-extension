/**
 * BurpSuite JavaScript Security Extension
 * Copyright (C) 2019  Focal Point Data Risk, LLC
 * Written by: Peter Hefley
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

import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.AAAARecord;
import org.xbill.DNS.CNAMERecord;
import org.xbill.DNS.SimpleResolver;

import java.util.HashMap;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

public class DNSResolver
{
    public static final Integer CNAME = 5;
    public static final Integer A = 1;
    public static final Integer AAAA = 28;
    private static final String RESOLVER_NAME = null;
    //private static final String RESOLVER_NAME = "8.8.8.8"; // Set this if you want a different resolver.
    private HashMap<String,Integer> typeLookup = new HashMap<String,Integer>();
    private SimpleResolver myResolver = null;


    public DNSResolver(){
        typeLookup.put("CNAME", CNAME);
        typeLookup.put("A", A);
        typeLookup.put("AAAA", AAAA);
        try {
            if (RESOLVER_NAME != null){
                myResolver = new SimpleResolver(RESOLVER_NAME);
            } else {
                myResolver = new SimpleResolver();
            }
        }
        catch (UnknownHostException e){
            System.err.print("[SRI][DNSResolver][-] could not bind DNS to resolver at " + RESOLVER_NAME);
        }
    }


    /**
     * A method to perform DNS queries using native Java
     * @param hostName a string of the hostname, or fqdn, to lookup 
     * @param type a string of the DNS record type to look up
     * @return a set of strings which are results of the DNS query
     */
    public Set<String> getRecords(String hostName, Integer type) {
        Set<String> retval = new TreeSet<String>();
        try {
            Lookup thisLookup = new Lookup(hostName, type);
            //thisLookup.setResolver(myResolver);
            Record[] results = thisLookup.run();
            if (results != null){
                List<Record> records = Arrays.asList(results);
                for (Record record : records){
                    if ((type == A) || (type == AAAA)){
                        if (type == A){
                            ARecord thisRecord = (ARecord) record;
                            retval.add(thisRecord.getAddress().getHostAddress());
                        } else {
                            AAAARecord thisRecord = (AAAARecord) record;
                            retval.add(thisRecord.getAddress().getHostAddress());
                        }
                    } else {
                        if (record.getType() == CNAME){
                            CNAMERecord thisRecord = (CNAMERecord) record;
                            retval.add(thisRecord.getTarget().toString());
                        } else {
                            retval.add(record.toString());
                        }
                    }
                }
            }
        }
        catch (TextParseException e){
            System.err.println("[SRI][-] There was an error parsing the name " + hostName);
        }        
        return retval;
    }


    /**
     * A method to perform DNS queries using native Java
     * @param hostName a string of the hostname, or fqdn, to lookup 
     * @param type a string of the DNS record type to look up
     * @return a set of strings which are results of the DNS query
     */
    public Set<String> getRecords(String hostName, String typeStr) {
        Set<String> retval = new TreeSet<String>();
        if (typeLookup.containsKey(typeStr)){
            retval.addAll(getRecords(hostName, typeLookup.get(typeStr)));
        }
        return retval;
    }


    /**
     * Follow the CNAME breadcrumb trail and find any which can't resolve
     * @param hostName a string of the hostname, or fqdn, to lookup 
     * @return a set of strings which list the CNAME entries which could not be resolved
     */
    public Set<String> getBadCnames(String hostName){
        Set<String> retval = new TreeSet<String>();
        try {
            Lookup thisLookup = new Lookup(hostName, CNAME);
            //thisLookup.setResolver(myResolver);
            Record[] results = thisLookup.run();
            if (results != null){
                List<Record> records = Arrays.asList(results);
                for (Record record : records){
                    CNAMERecord thisRecord = (CNAMERecord) record;
                    
                    String target = thisRecord.getTarget().toString();
                    System.out.println("[getbadcnames] from host " + hostName + " got a CNAME with target " + target);
                    if (hasRecordsOfType(target, CNAME)){
                        // check for more cnames down the tree
                        retval.addAll(getBadCnames(target));
                    } else {
                        if (!(hasRecordsOfType(target, A) || hasRecordsOfType(target, AAAA))){
                            // This one doesn't point to anything
                            retval.add(target);
                            System.out.println("[getbadcnames][-] from host " + hostName + " got a CNAME with target " + target + " which has no A or AAAA records");
                        }
                    }
                }
            }
        }
        catch (TextParseException e){
            System.err.println("[SRI][-] There was an error parsing the name " + hostName);
        }
        return retval;
    }
    
    /**
     * Are there any bad CNAMEs in the trail for this hostname?
     * @param hostName a string of the hostname, or fqdn, to lookup 
     * @return a boolean value, true if there are CNAME entries which cannot be resolved
     */
    public boolean hasBadCnames(String hostName){
        return (getBadCnames(hostName).size() > 0);
    }

    /**
     * Does the FQDN have any DNS entries of a given type?
     * @param hostName a string of the hostname, or fqdn, to lookup 
     * @param type a string of the DNS entry type
     * @return boolean, true if there are entries of the given type, false if not
     */
    public boolean hasRecordsOfType(String hostName, Integer type){
        return (getRecords(hostName, type).size() > 0);
    }

    public boolean hasRecordsOfType(String hostName, String typeStr){
        return (getRecords(hostName, typeStr).size() > 0);
    }

    /**
     * Does the given hostName have entries necessary to get a URL
     * @param hostName a string of the hostname, or fqdn, to lookup 
     * @return boolean, true if this shakes out and could be used to get a resource
     */
    public boolean hasValidRecordsForAUrl(String hostName){
        if ((hasRecordsOfType(hostName, A) || hasRecordsOfType(hostName, AAAA)) || hasRecordsOfType(hostName, CNAME)){
            // This should contain at least one record we can work with, but if it has CNAMEs let's lease them out
            if (hasRecordsOfType(hostName, "CNAME")){
                return (!hasBadCnames(hostName));
            } else {
                // Should be okay
                return true;
            }
        } else {
            return false;
        }
    }

    /**
     * Print a set of strings to stdout, one per line
     * @param setToPrint
     */
    public void printStringSet(Set<String> setToPrint){
        for (String item : setToPrint){
            System.out.println(item);
        }
    }

    /**
     * Print a set of strings to stderr, one per line
     * @param setToPrint
     */
    public void printStringSetToError(Set<String> setToPrint){
        for (String item : setToPrint){
            System.err.println(item);
        }
    }

}