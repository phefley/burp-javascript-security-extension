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

import java.util.List;
import java.util.ArrayList;

import org.focalpoint.isns.burp.srichecks.ScriptFinder;
import org.jsoup.nodes.Element;

public class ScriptFinderTest {
    @Test public void testUrlSetGet() {
        ScriptFinder testunit = new ScriptFinder();
        String testUrl = "https://code.jquery.com/jquery-3.3.1.js";
        testunit.setUrl(testUrl);
        assertEquals(testUrl, testunit.getUrl());
    }

    @Test public void testDriverStartStop() {
        ScriptFinder testunit = new ScriptFinder();
        testunit.setDriverPath("/usr/lib/chromium-browser/chromedriver");
        String testUrl = "https://code.jquery.com/jquery-3.3.1.js";
        testunit.startDriver();
        testunit.stopDriver();
        // If you get here without any errors, you did a good thing.
        assertTrue(true);
    }

    @Test public void testSetAndParseHtml() {
        String testUrl1 = "https://code.jquery.com/jquery-3.3.1abc.js";
        String testUrl2 = "https://code.jquery.com/jquery-3.3.1def.js";
        String testUrl = "https://code.jquery.com/test.html";
        String TEST_HTML = "<html><head><title>Thisisatest</title></head><body><script src=\""+ testUrl1 + "\"></script><b>Thisisstillatest</b><script src=\"" + testUrl2 + "\"></script></body></html>";
        ScriptFinder testunit = new ScriptFinder();
        testunit.setUrl(testUrl);
        testunit.setHtml(TEST_HTML);
        List<String> scripts = testunit.getHtmlScripts();
        assertTrue(scripts.contains(testUrl2));
        assertTrue(testunit.getScripts().contains(testUrl1));
    }

    @Test public void testScriptIsCrossDomain(){
        ScriptFinder testunit = new ScriptFinder();
        String testUrl = "https://code.jquery.com/jquery-3.3.1.js";
        String crossDomainScript = "https://www.notarealdomain.com/jquery-3.3.1.js";
        String notCrossDomainScript = "https://code.jquery.com/ascript.js";
        testunit.setUrl(testUrl);
        assertTrue(testunit.scriptIsCrossDomain(crossDomainScript));
        assertFalse(testunit.scriptIsCrossDomain(notCrossDomainScript));
    }

    @Test public void testDownloadHtml(){
        ScriptFinder testunit = new ScriptFinder();
        String testUrl = "https://www.focal-point.com";
        testunit.setDriverPath("/usr/lib/chromium-browser/chromedriver");
        testunit.setUrl(testUrl);
        assertEquals(testUrl, testunit.getUrl());
        testunit.retrieveHtml();
        assertTrue(testunit.getHtml().contains("Focal Point"));
    }

    @Test public void testCheckForDomScripts(){
        ScriptFinder testunit = new ScriptFinder();
        String testUrl = "https://www.focal-point.com";
        testunit.setDriverPath("/usr/lib/chromium-browser/chromedriver");
        testunit.setUrl(testUrl);
        testunit.retrieveHtml();
        testunit.checkForDomScripts();
        System.out.println("HTML SCRIPTS");
        System.out.println("============");
        for (String thisScript : testunit.getHtmlScripts()){
            System.out.println("* " + thisScript + " -- " + testunit.getHtmlTagFor(thisScript));
        }
        System.out.println();
        System.out.println("DOM SCRIPTS");
        System.out.println("============");
        for (String thisScript : testunit.getDomOnlyScripts()){
            System.out.println("* " + thisScript + " -- " + testunit.getHtmlTagFor(thisScript));
        }
        // If you get here without any errors, you did a good thing.
        assertTrue(true);
    }

    @Test public void runtimeTestFopo(){
        List<String> sriScripts = new ArrayList<>();
        List<String> sriMissingScripts = new ArrayList<>();
        String testUrl = "https://focal-point.com";
        ScriptFinder testunit = new ScriptFinder();
        testunit.setDriverPath("/usr/lib/chromium-browser/chromedriver");
        testunit.setUrl(testUrl);
        testunit.retrieveHtml();
        testunit.checkForDomScripts();

        // Go through all of the scripts and find those which have an integrity attribute and those which don't.
        for (String scriptUrl : testunit.getScripts()){
            String tag = testunit.getHtmlTagFor(scriptUrl);
            if (tag.contains("integrity=\"sha")){
                sriScripts.add(scriptUrl);
            }
            else {
                sriMissingScripts.add(scriptUrl);
            }
        }

        System.out.println(testUrl);
        System.out.println();
        System.out.println("HTML SCRIPTS");
        System.out.println("============");
        for (String thisScript : testunit.getHtmlScripts()){
            System.out.println("* \"" + thisScript + "\" -- " + testunit.getHtmlTagFor(thisScript));
        }
        System.out.println();
        System.out.println("DOM SCRIPTS");
        System.out.println("============");
        for (String thisScript : testunit.getDomOnlyScripts()){
            System.out.println("* \"" + thisScript + "\" -- " + testunit.getHtmlTagFor(thisScript));
        }
        System.out.println();
        System.out.println("SRI Scripts");
        System.out.println("===========");
        for (String thisScript : sriScripts){
            System.out.println("* \"" + thisScript + "\" -- " + testunit.getHtmlTagFor(thisScript));
        }
        System.out.println();
        System.out.println("SRI Missing Scripts");
        System.out.println("===================");
        for (String thisScript : sriMissingScripts){
            System.out.println("* \"" + thisScript + "\" -- " + testunit.getHtmlTagFor(thisScript));
        }
        // If you get here without any errors, you did a good thing.
        assertTrue(true);
    }

}
