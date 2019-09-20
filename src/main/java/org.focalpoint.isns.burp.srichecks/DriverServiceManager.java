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

import burp.IBurpExtenderCallbacks;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.support.ui.ExpectedCondition;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.openqa.selenium.StaleElementReferenceException;
import org.openqa.selenium.TimeoutException;

import org.openqa.selenium.chrome.ChromeDriverService;
import org.openqa.selenium.remote.RemoteWebDriver;
import java.io.File;
import java.io.IOException;
import java.io.FileOutputStream;
import java.io.InputStream;

public class DriverServiceManager {

    private String chromeDriverFilePath;
    private static String DEFAULT_DRIVER_PATH = "/usr/lib/chromium-browser/chromedriver";
    private final static String SETTING_CHROMEDRIVER_PATH = "jssecurity.chromedriverpath";
    private ChromeDriverService service;
    private IBurpExtenderCallbacks myCallbacks;

    public DriverServiceManager(){
        // Just default to the default driver path
        chromeDriverFilePath = DEFAULT_DRIVER_PATH;
    }

    public void setCallbacks(IBurpExtenderCallbacks cb){
        myCallbacks = cb;
        // Get the filepath setting
        if (myCallbacks.loadExtensionSetting(SETTING_CHROMEDRIVER_PATH) != null){
			chromeDriverFilePath = myCallbacks.loadExtensionSetting(SETTING_CHROMEDRIVER_PATH);
		}
    }


    public void startDriverService(){
        try{
            // https://seleniumhq.github.io/selenium/docs/api/java/
            File driverFile;
            driverFile = new File(chromeDriverFilePath);
            service = new ChromeDriverService.Builder().usingDriverExecutable(driverFile).usingAnyFreePort().build();
            service.start();
        }
        catch (IOException e){
            System.err.println("[JS-SRI][-] Could not start chromedriver service");
        }
        catch (IllegalStateException e){
            System.err.println("[JS-SRI][-] Could not start chromedriver service");
        }
    }

    public void stopDriverService(){
        if (service != null) {
            service.stop();
        }
    }

    public ChromeDriverService getService(){
        return service;
    }

    private void reloadIfRunning(){
        if (service != null){
            if (service.isRunning()){
                // Restart it
                stopDriverService();
                startDriverService();
            }
        }
    }

    private void reload(){
        if (service != null){
            if (service.isRunning()){
                stopDriverService();
            }
        }
        startDriverService();
    }

    public void setDriverPath(String path){
        chromeDriverFilePath = path;
        System.out.println("[JS-SRI] Set chromedriver path to " + path);
        reload();
    }

}