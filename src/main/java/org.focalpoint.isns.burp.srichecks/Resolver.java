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

import javax.naming.directory.DirContext;
import javax.naming.directory.Attributes;
import javax.naming.directory.InitialDirContext;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.NamingEnumeration;
import java.util.Set;
import java.util.Hashtable;
import java.util.TreeSet;

public class Resolver
{ 
    /**
     * A method to perform DNS queries using native Java
     * Reference: http://www.devguerrilla.com/notes/2014/10/java-looking-up-dns-entries-with-jndi/
     * @param hostName a string of the hostname, or fqdn, to lookup 
     * @param type a string of the DNS record type to look up
     * @return a set of strings which are results of the DNS query
     */
    public Set<String> getRecords(String hostName, String type) {
        Set<String> results = new TreeSet<String>();
        try {
            Hashtable<String, String> envProps = new Hashtable<String, String>();
            envProps.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");
            DirContext dnsContext = new InitialDirContext(envProps);
            Attributes dnsEntries = dnsContext.getAttributes(hostName, new String[]{type});
            if(dnsEntries != null) {
                if (dnsEntries.get(type) != null){
                    NamingEnumeration<?> dnsEntryIterator = dnsEntries.get(type).getAll();
                    while(dnsEntryIterator.hasMoreElements()) {
                        results.add(dnsEntryIterator.next().toString());
                    }
                }
            }
            //envProps.remove(Context.INITIAL_CONTEXT_FACTORY);
        } catch(NamingException e) {
            System.err.println(e.toString());
            e.printStackTrace();
        }
        return results;
    }

    /**
     * Get all of the record types available
     * 
     * Note - this may not work on some DNS servers due to https://datatracker.ietf.org/doc/rfc8482/
     * @param hostName a string of the hostname, or fqdn, to lookup 
     * @return a set of strings which contains the results of all records available, prepended with the record type
     */
    public Set<String> getAllRecords(String hostName) {
        Set<String> results = new TreeSet<String>();
        try {
            Hashtable<String, String> envProps = new Hashtable<String, String>();
            envProps.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");
            DirContext dnsContext = new InitialDirContext(envProps);
            Attributes dnsEntries = dnsContext.getAttributes(hostName,new String[]{"*"});
            if(dnsEntries != null) {
                NamingEnumeration<?> dnsEntryIterator = dnsEntries.getAll();
                while(dnsEntryIterator.hasMoreElements()) {
                    results.add(dnsEntryIterator.next().toString());
                }
            }
            //envProps.remove(Context.INITIAL_CONTEXT_FACTORY);
        } catch(NamingException e) {
            System.err.println(e.toString());
            e.printStackTrace();
        }
        return results;
    }


    /**
     * Get all of the record types available for a hostname
     * 
     * Note - this may not work on some DNS servers due to https://datatracker.ietf.org/doc/rfc8482/
     * @param hostName a string of the hostname, or fqdn, to lookup 
     * @return a set of strings which indicate all of the DNS types available
     */
    public Set<String> getAllRecordTypes(String hostName) {
        Set<String> results = new TreeSet<String>();
        try {
            Hashtable<String, String> envProps = new Hashtable<String, String>();
            envProps.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");
            DirContext dnsContext = new InitialDirContext(envProps);
            Attributes dnsEntries = dnsContext.getAttributes(hostName,new String[]{"*"});
            if(dnsEntries != null) {
                NamingEnumeration<?> dnsEntryIterator = dnsEntries.getIDs();
                while(dnsEntryIterator.hasMoreElements()) {
                    results.add(dnsEntryIterator.next().toString());
                }
            }
            //envProps.remove(Context.INITIAL_CONTEXT_FACTORY);
        } catch(NamingException e) {
            System.err.println(e.toString());
            e.printStackTrace();
        }
        return results;
    }

    /**
     * Follow the CNAME breadcrumb trail and find any which can't resolve
     * @param hostName a string of the hostname, or fqdn, to lookup 
     * @return a set of strings which list the CNAME entries which could not be resolved
     */
    public Set<String> getBadCnames(String hostName){
        Set<String> results = new TreeSet<String>();
        Set<String> cnames = new TreeSet<String>();
        cnames = getRecords(hostName, "CNAME");
        while (!cnames.isEmpty()){
            String thisCname = (String) cnames.toArray()[0];
            // If there are CNAMEs, add them
            if (hasRecordsOfType(thisCname, "CNAME")){
                cnames.addAll(getRecords(thisCname, "CNAME"));
            }
            // If the set is empty, it didn't resolve
            if (!(hasValidRecordsForAUrl(thisCname))){
                results.add(thisCname);
            }
            cnames.remove(thisCname);
        }
        return results;
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
    public boolean hasRecordsOfType(String hostName, String type){
        return (getRecords(hostName, type).size() > 0);
    }


    /**
     * Does the given hostName have entries necessary to get a URL
     * @param hostName a string of the hostname, or fqdn, to lookup 
     * @return boolean, true if this shakes out and could be used to get a resource
     */
    public boolean hasValidRecordsForAUrl(String hostName){
        if ((hasRecordsOfType(hostName, "A") || hasRecordsOfType(hostName, "AAAA")) || hasRecordsOfType(hostName, "CNAME")){
            // This should contain at least one record we can work with, but if it has CNAMEs let's lease them out
            if (hasRecordsOfType(hostName, "CNAME")){
                return (!hasBadCnames(hostName));
            } else {
                // Should be okay
                return true;
            }
        }
        else {
            // Try one last ditch effort
            Set<String> recordTypes = getAllRecordTypes(hostName);
            if ((recordTypes.contains("A") || recordTypes.contains("AAAA")) || recordTypes.contains("CNAME")){
                // This should contain at least one record we can work with, but if it has CNAMEs let's lease them out
                if (hasRecordsOfType(hostName, "CNAME")){
                    return (!hasBadCnames(hostName));
                } else {
                    // Should be okay
                    return true;
                }
            } else {
                // This doesn't have any of the record types I would expect for a URL
                return false;
            }
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