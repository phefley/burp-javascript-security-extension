package org.focalpoint.isns.burp.srichecks;

import org.junit.Test;
import static org.junit.Assert.*;
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

    /*
    @Test public void testGetResource() {
        JavascriptResource testunit = new JavascriptResource();
        String testUrl = "https://code.jquery.com/jquery-3.3.1.js";
        testunit.setSrc(testUrl);
        testunit.getResource();
        assertTrue(testunit.hasData());;
    }

    @Test public void testHashing() {
        JavascriptResource testunit = new JavascriptResource();
        String testUrl = "https://code.jquery.com/jquery-3.3.1.js";
        testunit.setSrc(testUrl);
        testunit.getResource();
        testunit.calculateHashes();
        String integrityValue = "sha256-2Kok7MbOyxpgUVvAk/HJ2jigOSYS2auK4Pfzbm7uH60="; // obtained from the jquery website
        assertEquals(integrityValue.substring(integrityValue.indexOf("-")+1), testunit.getHashes().get("sha256"));
    }

    @Test public void testIntegrity() {
        JavascriptResource testunit = new JavascriptResource();
        String testUrl = "https://code.jquery.com/jquery-3.3.1.js";
        testunit.setSrc(testUrl);
        testunit.getResource();
        testunit.calculateHashes();
        String originalTag = "<script src=\"https://code.jquery.com/jquery-3.3.1.js\" integrity=\"sha256-2Kok7MbOyxpgUVvAk/HJ2jigOSYS2auK4Pfzbm7uH60=\" crossorigin=\"anonymous\"></script>";
        testunit.setOriginalTag(originalTag);
        assertTrue(testunit.checkIntegrity());
    } */
}
