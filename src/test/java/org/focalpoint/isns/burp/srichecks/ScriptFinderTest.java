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

import java.util.List;
import java.util.ArrayList;

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
        DriverServiceManager sm = new DriverServiceManager();
        sm.startDriverService();
        testunit.setDriverManager(sm);
        String testUrl = "https://code.jquery.com/jquery-3.3.1.js";
        testunit.startDriver();
        testunit.stopDriver();
        // If you get here without any errors, you did a good thing.
        assertTrue(true);
    }

    @Test public void testUrlConditioning() {
        String testUrl1 = "jquery-3.3.1.min.js";
        String testUrl = "https://code.jquery.com/test.html";
        ScriptFinder testunit = new ScriptFinder();
        String conditionedUrl = testunit.conditionReceivedUrl(testUrl1, testUrl);
        System.out.println("testing url conditioning...");
        System.out.println(conditionedUrl);
        assertTrue(conditionedUrl.equals("https://code.jquery.com/jquery-3.3.1.min.js"));
    }

    @Test public void testSetAndParseHtml() {
        String testUrl1 = "https://code.jquery.com/jquery-3.3.1.min.js";
        String testUrl2 = "https://code.jquery.com/jquery-3.3.1.js";
        String testUrl = "https://code.jquery.com/test.html";
        String TEST_HTML = "<html><head><title>Thisisatest</title></head><body><script src=\""+ testUrl1 + "\"></script><b>Thisisstillatest</b><script src=\"" + testUrl2 + "\"></script></body></html>";
        ScriptFinder testunit = new ScriptFinder();
        testunit.setUrl(testUrl);
        testunit.setHtml(TEST_HTML);
        List<String> scripts = testunit.getHtmlScripts();
        System.out.println("testSetAndParseHtml");
        for (String scrSrc : scripts){
            System.out.println(" - " + scrSrc);
        }
        System.out.println();
        assertTrue(testunit.getScripts().contains(testUrl2));
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
        String testUrl = "https://focal-point.com";
        DriverServiceManager sm = new DriverServiceManager();
        testunit.setDriverManager(sm);
        testunit.setUrl(testUrl);
        assertEquals(testUrl, testunit.getUrl());
        testunit.retrieveHtml();
        assertTrue(testunit.getHtml().contains("Focal Point"));
    }

    @Test public void testCheckForDomScripts(){
        ScriptFinder testunit = new ScriptFinder();
        String testUrl = "https://focal-point.com";
        DriverServiceManager sm = new DriverServiceManager();
        sm.startDriverService();
        testunit.setDriverManager(sm);
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
        System.out.println("\n\n");
        // If you get here without any errors, you did a good thing.
        assertTrue(true);
    }

    @Test public void runtimeTestFopo(){
        final String KNOWN_HTML_SCRIPT = "https://js.hs-scripts.com/2762002.js";
        final String KNOWN_DOM_SCRIPT = "https://js.usemessages.com/conversations-embed.js";

        List<String> sriScripts = new ArrayList<>();
        List<String> sriMissingScripts = new ArrayList<>();
        String testUrl = "https://focal-point.com";
        ScriptFinder testunit = new ScriptFinder();
        DriverServiceManager sm = new DriverServiceManager();
        sm.startDriverService();
        testunit.setDriverManager(sm);
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

        // Check cross domain scripts
        assertTrue(testunit.getCrossDomainScripts().contains(KNOWN_DOM_SCRIPT));
        assertTrue(testunit.getCrossDomainScripts().contains(KNOWN_HTML_SCRIPT));
        assertTrue(testunit.getCrossDomainHtmlScripts().contains(KNOWN_HTML_SCRIPT));
        assertTrue(testunit.getCrossDomainDomScripts().contains(KNOWN_DOM_SCRIPT));

        System.out.println(testUrl);
        System.out.println();
        System.out.println("HTML SCRIPTS");
        System.out.println("============");
        List<String> htmlScripts = testunit.getHtmlScripts();
        for (String thisScript : htmlScripts){
            System.out.println("* \"" + thisScript + "\" -- " + testunit.getHtmlTagFor(thisScript));
        }
        // Check for the known HTML script
        assertTrue(htmlScripts.contains(KNOWN_HTML_SCRIPT));
        // Check to make sure the DOM script isn't there
        assertFalse(htmlScripts.contains(KNOWN_DOM_SCRIPT));

        System.out.println();
        System.out.println("DOM SCRIPTS");
        System.out.println("============");
        List<String> domScripts = testunit.getDomOnlyScripts();
        for (String thisScript : domScripts){
            System.out.println("* \"" + thisScript + "\" -- " + testunit.getHtmlTagFor(thisScript));
        }
        // Check for the known DOM script
        assertTrue(domScripts.contains(KNOWN_DOM_SCRIPT));
        // Check to make sure the HTML script isn't there
        assertFalse(domScripts.contains(KNOWN_HTML_SCRIPT));

        System.out.println();
        System.out.println("SRI Scripts");
        System.out.println("===========");
        for (String thisScript : sriScripts){
            System.out.println("* \"" + thisScript + "\" -- " + testunit.getHtmlTagFor(thisScript));
        }
        // There should not be any
        assertEquals(0, sriScripts.size());

        System.out.println();
        System.out.println("SRI Missing Scripts");
        System.out.println("===================");
        for (String thisScript : sriMissingScripts){
            System.out.println("* \"" + thisScript + "\" -- " + testunit.getHtmlTagFor(thisScript));
        }
        // Check for both known scripts in sriMissing
        assertTrue(sriMissingScripts.contains(KNOWN_DOM_SCRIPT));
        assertTrue(sriMissingScripts.contains(KNOWN_HTML_SCRIPT));

        // If you get here without any errors, you did a good thing.
        assertTrue(true);
    }

}
