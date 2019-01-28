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

import org.junit.Test;
import static org.junit.Assert.*;
import java.util.Set;

public class DNSResolverTest {

    @Test public void testResolution() {
        DNSResolver testunit = new DNSResolver();
        String testHost = "focal-point.com";
        Set<String> results = testunit.getRecords(testHost, "A");
        assertTrue(results.size() > 0);
    }


    @Test public void testCnameChain() {
        DNSResolver testunit = new DNSResolver();
        String testHost = "sjs.bizographics.com";
        System.out.println("Testing for bad CNAMES...");
        testunit.printStringSet(testunit.getBadCnames(testHost));
        assertFalse(testunit.hasBadCnames(testHost));
    }


    @Test public void testForValidUrl() {
        DNSResolver testunit = new DNSResolver();
        String testHost = "js.hs-scripts.com";
        assertTrue(testunit.hasValidRecordsForAUrl(testHost));
    }

}
