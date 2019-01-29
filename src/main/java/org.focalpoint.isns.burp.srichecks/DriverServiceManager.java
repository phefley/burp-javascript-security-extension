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

    // DRIVER PATHS in resources
    private final String LINUX_DRIVER_RESOURCE_PATH = "/linux/chromedriver";
    private final String MAC_DRIVER_RESOURCE_PATH = "/mac/chromedriver";
    private final String WINDOWS_DRIVER_RESOURCE_PATH = "/windows/chromedriver.exe";

    private Boolean overrideResourceBinaries = false;
    private String chromeDriverFilePath;

    private ChromeDriverService service;

    public DriverServiceManager(){
        startDriverService();
    }

    private File getDriverResourceFile(){
        String osName = System.getProperty("os.name").toLowerCase();
        String fileName = null;
        boolean needToChmod = false;
        if (osName.contains("linux")){
            fileName = LINUX_DRIVER_RESOURCE_PATH;
            needToChmod = true;
        } else {
            if (osName.contains("windows")){
                fileName = WINDOWS_DRIVER_RESOURCE_PATH;
            } else {
                if (osName.contains("mac")){
                    fileName = MAC_DRIVER_RESOURCE_PATH;
                    needToChmod = true;
                }
            }
        }
        File retval = null;
        if (fileName != null){
            retval = getResourceAsFile(fileName);
            if (needToChmod) {
                retval.setExecutable(true);
            }
        }
        return retval;
    }


    private File getResourceAsFile(String resourcePath) {
        try {
            InputStream in = this.getClass().getResourceAsStream(resourcePath);
            if (in == null) {
                return null;
            }
    
            File tempFile = File.createTempFile(String.valueOf(in.hashCode()), ".tmp");
            tempFile.deleteOnExit();
    
            try (FileOutputStream out = new FileOutputStream(tempFile)) {
                //copy stream
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = in.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                }
            }
            return tempFile;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }


    public void startDriverService(){
        try{
            // https://seleniumhq.github.io/selenium/docs/api/java/
            File driverFile;
            if (overrideResourceBinaries){
                driverFile = new File(chromeDriverFilePath);
            } else {
                driverFile = getDriverResourceFile();
            }
            service = new ChromeDriverService.Builder().usingDriverExecutable(driverFile).usingAnyFreePort().build();
            service.start();
        }
        catch (IOException e){
            System.err.println("[JS-SRI][-] Could not start chromedriver service");
        }
    }

    public void stopDriverService(){
        service.stop();
    }

    public ChromeDriverService getService(){
        return service;
    }

    private void reloadIfRunning(){
        if (service.isRunning()){
            // Restart it
            stopDriverService();
            startDriverService();
        }
    }

    public void useBundledDrivers(){
        overrideResourceBinaries = false;
        reloadIfRunning();
    }

    public void setOverrideDriverPath(String path){
        overrideResourceBinaries = true;
        chromeDriverFilePath = path;
        reloadIfRunning();
    }

}