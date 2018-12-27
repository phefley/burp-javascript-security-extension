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
