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
import org.jsoup.nodes.Element;

public class JavaScriptIOCTest {
    @Test public void testSourceSetGet() {
        JavaScriptIOC testunit = new JavaScriptIOC();
        String testUrl = "https://code.jquery.com/jquery-3.3.1.js";
        testunit.setSource(testUrl);
        assertEquals(testUrl, testunit.getSource());
    }

    @Test public void testUrlSetGet() {
        JavaScriptIOC testunit = new JavaScriptIOC();
        String testUrl = "https://code.jquery.com/jquery-3.3.1.js";
        testunit.setUrl(testUrl);
        assertEquals(testUrl, testunit.getUrl());
    }

    @Test public void testHashAddGet() {
        String algorithm = "md5";
        String hashValue = "0cbc4295afe8e9a9341ce9db57801aa8";
        JavaScriptIOC testunit = new JavaScriptIOC();
        testunit.addHash(algorithm, hashValue);
        assertEquals(hashValue, testunit.getHash(algorithm));
    }
}
