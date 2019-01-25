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

import java.util.HashMap;

import org.jsoup.nodes.Element;

public class JavascriptResourceTest {
    @Test public void testSrcSetGet() {
        JavascriptResource testunit = new JavascriptResource();
        String testUrl = "https://code.jquery.com/jquery-3.3.1.js";
        testunit.setSrc(testUrl);
        assertEquals(testUrl, testunit.getSrc());
    }

    @Test public void testOriginalTagSetGet() {
        JavascriptResource testunit = new JavascriptResource();
        String testUrl = "https://code.jquery.com/jquery-3.3.1.js";
        String testTag = "<script src=\"" + testUrl + "\"></script>";
        testunit.setSrc(testUrl);
        testunit.setOriginalTag(testTag);
        assertEquals(testTag, testunit.getOriginalTag());
    }

    @Test public void testTagParser() {
        JavascriptResource testunit = new JavascriptResource();
        String testUrl = "https://code.jquery.com/jquery-3.3.1.js";
        String testTag = "<script src=\"" + testUrl + "\"></script>";
        testunit.setSrc(testUrl);
        testunit.setOriginalTag(testTag);
        testunit.parseTag();
        Element parsedTag = testunit.getParsedTag();
        assertEquals(testUrl, parsedTag.attr("src"));
    }


    @Test public void testGetResource() {
        JavascriptResource testunit = new JavascriptResource();
        String testUrl = "https://code.jquery.com/jquery-3.3.1.js";
        testunit.setSrc(testUrl);
        testunit.setCallbacks(null);
        testunit.getResource();
        assertTrue(testunit.hasData());;
    }

    @Test public void testHashing() {
        JavascriptResource testunit = new JavascriptResource();
        String testUrl = "https://code.jquery.com/jquery-3.3.1.js";
        testunit.setSrc(testUrl);
        testunit.setCallbacks(null);
        testunit.getResource();
        testunit.calculateHashes();
        String integrityValue = "sha256-2Kok7MbOyxpgUVvAk/HJ2jigOSYS2auK4Pfzbm7uH60="; // obtained from the jquery website
        assertEquals(integrityValue.substring(integrityValue.indexOf("-")+1), testunit.getHashes().get("sha256"));
    }

    @Test public void testIntegrity() {
        String testUrl = "https://code.jquery.com/jquery-3.3.1.min.js";
        String originalTag = "<script src=\"https://code.jquery.com/jquery-3.3.1.min.js\" integrity=\"sha256-FgpCb/KJQlLNfOu91ta32o/NMZxltwRo8QtmkMRdAu8=\" crossorigin=\"anonymous\"></script>";
        JavascriptResource testunit = new JavascriptResource(null, testUrl, originalTag);
        System.out.println("Integrity Testing");
        System.out.println("-----------------");
        System.out.println("Original tag: " + originalTag);
        System.out.println("Hashes:");
        HashMap<String,String> hashes = testunit.getHashes();
        for (String hashAlgo : hashes.keySet()){
            System.out.println("\t" + hashAlgo + " : " + hashes.get(hashAlgo));
        }
        System.out.println();
        System.out.println(testunit.getData());
        assertTrue(testunit.checkIntegrity());
    }

    @Test public void testGithubIntegrity() {
        String testUrl = "https://github.githubassets.com/assets/compat-6e5ed2648dae3be3f9358af5732a780f.js";
        String originalTag = "<script crossorigin=\"anonymous\" integrity=\"sha512-Mp0nAOFvmE8PVQP49TPVMbQBLb+lpf3gu9GF1CPqybGGzl/8KEKDTKzuJpxxd5xF8HUi85xKPkssLtVVdLKtlw==\" type=\"application/javascript\" src=\"https://github.githubassets.com/assets/compat-6e5ed2648dae3be3f9358af5732a780f.js\"></script>";
        JavascriptResource testunit = new JavascriptResource(null, testUrl, originalTag);
        System.out.println("Github Integrity Testing");
        System.out.println("-----------------");
        System.out.println("Original tag: " + originalTag);
        System.out.println("Hashes:");
        HashMap<String,String> hashes = testunit.getHashes();
        for (String hashAlgo : hashes.keySet()){
            System.out.println("\t" + hashAlgo + " : " + hashes.get(hashAlgo));
        }
        System.out.println();
        System.out.println(testunit.getData());
        assertTrue(testunit.checkIntegrity());
    }
}
