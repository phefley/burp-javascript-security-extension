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
