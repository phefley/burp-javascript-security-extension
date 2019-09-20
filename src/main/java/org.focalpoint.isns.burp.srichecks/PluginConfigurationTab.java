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

import java.awt.Color;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Label;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.SpringLayout;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.JButton;

import burp.IBurpExtenderCallbacks;

import java.io.File;

public class PluginConfigurationTab extends JPanel implements ActionListener{
	private static PluginConfigurationTab panel;
	private static final Integer defaultDelay = 10;
	
	private JLabel delayLabel;
    private JTextField delayTextField;
    private JLabel driverChooserLabel;
	private JFileChooser driverChooser;
	private JTextField filePathField;
	private Label titleLabel;
	private JButton openChooserButton;

	private Label iocLabel;
	private JTextField iocCountField;
	private JButton openIocFileButton;
	private JFileChooser iocChooser;

	private IBurpExtenderCallbacks extensionCallbacks;
	
	private final static Integer MAX_FILE_FIELD_COLS = 60;
	private final static Integer MAX_DELAY_COLS = 3;
	private final static Integer MAX_IOC_FIELD_COLS = 3;
	private final static String SETTING_CHROMEDRIVER_PATH = "jssecurity.chromedriverpath";
	private IoCChecker myIocChecker;

	private DriverServiceManager myServiceManager;
	
	/**
	 * Default constructor
	 */
	public PluginConfigurationTab() {
		//render();
	}
	
	/** 
	 * Get this instance
	 * @return this instance
	 */
	public static PluginConfigurationTab getInstance() {
		if(panel == null)
			panel = new PluginConfigurationTab();
		return panel;
	}
	
	/**
	 * Set the IOC checker, linking the two so that the IOCs can be loaded
	 * @param iocs An IOCChecker object used.
	 */
	public void setIocChecker(IoCChecker iocs){
		myIocChecker = iocs;
	}

	/**
	 * Set the callbacks object so configurations can be updated by the panel
	 * @param cb The extensions call back object
	 */
	public void setCallbacks(IBurpExtenderCallbacks cb){
		extensionCallbacks = cb;
	}

	/**
	 * Set the driver service manager, linking the two so that the driver path can be modified
	 * @param sm A driver service manager object to use
	 */
	public void setDriverServiceManager(DriverServiceManager sm){
		myServiceManager = sm;
	}


	/**
	 * Render the view
	 */
	public void render() {
		SpringLayout layout = new SpringLayout();
		setLayout(layout);
        titleLabel = new Label("DOM Check Settings");
		titleLabel.setForeground(new Color(229, 137, 0));
		titleLabel.setFont(new Font("Dialog", Font.BOLD, 15));
		layout.putConstraint(SpringLayout.NORTH, titleLabel, 5, SpringLayout.NORTH, getInstance());
		layout.putConstraint(SpringLayout.WEST, titleLabel, 5, SpringLayout.WEST, getInstance());

		// Driver chooser wiring
		driverChooser = new JFileChooser();

		// Try to set a default based on a standard. Linux install location
		if (extensionCallbacks.loadExtensionSetting(SETTING_CHROMEDRIVER_PATH) != null){
			File settingDriverPath = new File(extensionCallbacks.loadExtensionSetting(SETTING_CHROMEDRIVER_PATH));
			driverChooser.setSelectedFile(settingDriverPath);
		} else {
			File defaultDriver = new File("/usr/lib/chromium-browser/chromedriver");
			driverChooser.setSelectedFile(defaultDriver);
		}

		driverChooserLabel = new JLabel("Select the chromedriver to use:");
		layout.putConstraint(SpringLayout.NORTH, driverChooserLabel, 5, SpringLayout.SOUTH, titleLabel);
		layout.putConstraint(SpringLayout.WEST, driverChooserLabel, 5, SpringLayout.WEST, getInstance());

		filePathField = new JTextField(getDriverPath());
		filePathField.setColumns(MAX_FILE_FIELD_COLS);
		filePathField.setEditable(false);
		layout.putConstraint(SpringLayout.WEST, filePathField, 5, SpringLayout.EAST, driverChooserLabel);
		layout.putConstraint(SpringLayout.NORTH, filePathField, 5, SpringLayout.SOUTH, titleLabel);

		openChooserButton = new JButton("Select Driver...");
		openChooserButton.addActionListener(this);
		layout.putConstraint(SpringLayout.WEST, openChooserButton, 5, SpringLayout.WEST, getInstance());
		layout.putConstraint(SpringLayout.NORTH, openChooserButton, 5, SpringLayout.SOUTH, driverChooserLabel);

		// Delay wiring
		delayLabel = new JLabel("Delay (in seconds) to wait for the DOM to load:");
		layout.putConstraint(SpringLayout.WEST, delayLabel, 5, SpringLayout.WEST, getInstance());
		layout.putConstraint(SpringLayout.NORTH, delayLabel, 20, SpringLayout.SOUTH, openChooserButton);

		delayTextField = new JTextField(defaultDelay.toString());
		delayTextField.setColumns(MAX_DELAY_COLS);
		layout.putConstraint(SpringLayout.WEST, delayTextField, 5, SpringLayout.EAST, delayLabel);
		layout.putConstraint(SpringLayout.NORTH, delayTextField, 20, SpringLayout.SOUTH, openChooserButton);

		// IoC wiring
		iocLabel = new Label("IoC Count: ");
		layout.putConstraint(SpringLayout.WEST, iocLabel, 5, SpringLayout.WEST, getInstance());
		layout.putConstraint(SpringLayout.NORTH, iocLabel, 20, SpringLayout.SOUTH, delayLabel);
		iocCountField = new JTextField(myIocChecker.getIocCount().toString());
		iocCountField.setColumns(MAX_IOC_FIELD_COLS);
		iocCountField.setEditable(false);
		layout.putConstraint(SpringLayout.WEST, iocCountField, 5, SpringLayout.EAST, iocLabel);
		layout.putConstraint(SpringLayout.NORTH, iocCountField, 20, SpringLayout.SOUTH, delayLabel);
		iocChooser = new JFileChooser();
		openIocFileButton = new JButton("Import IoCs");
		openIocFileButton.addActionListener(this);
		layout.putConstraint(SpringLayout.WEST, openIocFileButton, 5, SpringLayout.EAST, iocCountField);
		layout.putConstraint(SpringLayout.NORTH, openIocFileButton, 20, SpringLayout.SOUTH, delayLabel);


		// add to Pane
		add(titleLabel);
		add(driverChooserLabel);
		add(filePathField);
		add(openChooserButton);
		add(delayLabel);
		add(delayTextField);
		add(iocLabel);
		add(iocCountField);
		add(openIocFileButton);
	}

	/**
	 * Get the delay from the GUI as an integer
	 * If there's not an integer which can be parsed, reset this to the default
	 * @return the delay (in seconds, as an integer)
	 */
	public Integer getDelay() {
		try {
			return Integer.parseInt(delayTextField.getText());
		} 
		catch (NumberFormatException e){
			delayTextField.setText(defaultDelay.toString());
			return defaultDelay;
		}
	}
	
	/**
	 * Get the driver file path for the chromedriver which should be used by Seleniu, from the GUI
	 * @return a String which is the path to the chromedriver binary picked by the user in the GUI
	 */
	public String getDriverPath() {
		return driverChooser.getSelectedFile().getAbsolutePath();
    }

	/** 
	 * Handle actions performed within the GUI
	 * @param e an actionevent which occurred in the GUI
	 */
    public void actionPerformed(ActionEvent e){
        // Handle the select button
		if (e.getSource() == openChooserButton){
			int returnVal = driverChooser.showDialog(this, "Select Driver");
			if (returnVal == JFileChooser.APPROVE_OPTION){
				System.out.println("[JS-SRI][*] Selected " + getDriverPath() + " as the chrome-driver.");
				filePathField.setText(getDriverPath());
				myServiceManager.setDriverPath(getDriverPath());
				extensionCallbacks.saveExtensionSetting(SETTING_CHROMEDRIVER_PATH, getDriverPath());
			}
		}
		// Handle the open IOC Button
		if (e.getSource() == openIocFileButton){
			int returnVal = iocChooser.showOpenDialog(this);
			if (returnVal == JFileChooser.APPROVE_OPTION){
				String filePath = iocChooser.getSelectedFile().getAbsolutePath();
				System.out.println("[JS-SRI][*] Selected " + filePath + " for IoC import.");
				myIocChecker.importIocsFromJson(filePath);
				iocCountField.setText(myIocChecker.getIocCount().toString());
				System.out.println("[JS-SRI][*] Imported IoCs from " + filePath + ".");
			}
		}
    }
}