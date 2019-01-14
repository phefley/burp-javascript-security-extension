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

import org.junit.Test;
import static org.junit.Assert.*;

import org.focalpoint.isns.burp.srichecks.IoCChecker;
import org.focalpoint.isns.burp.srichecks.JavaScriptIOC;
import java.util.HashMap;

public class IoCCheckerTest {
    @Test public void testCheckUrl() {
        // Checks to make sure that you can check a URL and obtain the correct source for it.
        IoCChecker testunit = new IoCChecker();
        String testSource = "This is a source";
        String testUrl = "https://www.focal-point.com";
        testunit.addIoc(new JavaScriptIOC(testSource, testUrl));
        assertTrue(testunit.checkUrl(testUrl));
        assertEquals(testSource, testunit.getUrlSource(testUrl));
    }

    @Test public void testCheckHash() {
        // Tests to make sure that you can check a algorithm/hash pair and obtain the source.
        String algorithm = "md5";
        String hashValue = "0cbc4295afe8e9a9341ce9db57801aa8";
        String testSource = "This is a source";
        JavaScriptIOC testioc = new JavaScriptIOC();
        testioc.addHash(algorithm, hashValue);
        testioc.setSource(testSource);
        IoCChecker testunit = new IoCChecker();
        testunit.addIoc(testioc);
        HashMap<String,String> hashLookup = new HashMap<String,String>();
        hashLookup.put(algorithm, hashValue);
        assertTrue(testunit.checkHash(algorithm, hashValue));
        assertTrue(testunit.checkHashes(hashLookup));
        assertEquals(testSource, testunit.getHashSource(algorithm, hashValue));
    }
}
