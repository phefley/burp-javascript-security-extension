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
	private final static Integer MAX_FILE_FIELD_COLS = 60;
	private final static Integer MAX_DELAY_COLS = 3;
	
	public PluginConfigurationTab() {
		//render();
	}
	
	public static PluginConfigurationTab getInstance() {
		if(panel == null)
			panel = new PluginConfigurationTab();
		return panel;
	}
	
	public void render() {
		SpringLayout layout = new SpringLayout();
		setLayout(layout);
        titleLabel = new Label("DOM Check Settings");
		titleLabel.setForeground(new Color(229, 137, 0));
		titleLabel.setFont(new Font("Dialog", Font.BOLD, 15));
		layout.putConstraint(SpringLayout.NORTH, titleLabel, 5, SpringLayout.NORTH, getInstance());
		layout.putConstraint(SpringLayout.WEST, titleLabel, 5, SpringLayout.WEST, getInstance());

		driverChooser = new JFileChooser();
		// Try to set a default based on a standard. Linux install location
		File defaultDriver = new File("/usr/lib/chromium-browser/chromedriver");
		driverChooser.setSelectedFile(defaultDriver);

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

		delayLabel = new JLabel("Delay (in seconds) to wait for the DOM to load:");
		layout.putConstraint(SpringLayout.WEST, delayLabel, 5, SpringLayout.WEST, getInstance());
		layout.putConstraint(SpringLayout.NORTH, delayLabel, 20, SpringLayout.SOUTH, openChooserButton);

		delayTextField = new JTextField(defaultDelay.toString());
		delayTextField.setColumns(MAX_DELAY_COLS);
		layout.putConstraint(SpringLayout.WEST, delayTextField, 5, SpringLayout.EAST, delayLabel);
		layout.putConstraint(SpringLayout.NORTH, delayTextField, 20, SpringLayout.SOUTH, openChooserButton);

		// add to Pane
		add(titleLabel);
		add(driverChooserLabel);
		add(filePathField);
		add(openChooserButton);
		add(delayLabel);
		add(delayTextField);
	}

	public Integer getDelay() {
		try {
			return Integer.parseInt(delayTextField.getText());
		} 
		catch (NumberFormatException e){
			delayTextField.setText(defaultDelay.toString());
			return defaultDelay;
		}
	}
	
	public String getDriverPath() {
		return driverChooser.getSelectedFile().getAbsolutePath();
    }
    
    public void actionPerformed(ActionEvent e){
        // Handle the select button
		if (e.getSource() == openChooserButton){
			int returnVal = driverChooser.showDialog(this, "Select Driver");
			if (returnVal == JFileChooser.APPROVE_OPTION){
				System.out.println("[FOPO-SRI][*] Selected " + getDriverPath() + " as the chrome-driver.");
				filePathField.setText(getDriverPath());
			}
		}
    }
}