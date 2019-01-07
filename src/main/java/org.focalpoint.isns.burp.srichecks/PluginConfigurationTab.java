package org.focalpoint.isns.burp.srichecks;

import java.awt.Color;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Label;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.JButton;

public class PluginConfigurationTab extends JPanel implements ActionListener{

	private static final long serialVersionUID = -3439093083112839349L;
	private static PluginConfigurationTab panel;
	private static final Integer defaultDelay = 10;
	
	
	// ************************
	// * Common
	// ************************
	private JLabel delayLabel;
    private JTextField delayTextField;
    private JLabel driverChooserLabel;
    private JFileChooser driverChooser;
	private Label titleLabel;
	private JButton openChooserButton;
	
	
	/** Minimum Space between right side of syncScrollpane and that of this pane. */
	//private static final int MINIMUM_SPACE_OF_SYNCPANE_RIGHTSIDE = 100;
	
	private PluginConfigurationTab() {
		render();
	}
	
	public static PluginConfigurationTab getInstance() {
		if(panel == null)
			panel = new PluginConfigurationTab();
		return panel;
	}
	
	public void render() {
		setLayout(null);
        titleLabel = new Label("DOM Check Settings");
		titleLabel.setForeground(new Color(229, 137, 0));
		titleLabel.setFont(new Font("Dialog", Font.BOLD, 15));
		
		driverChooserLabel = new JLabel("Select the chromedriver to use:");

		openChooserButton = new JButton("Select Driver...");
		openChooserButton.addActionListener(this);


		// set location and size
		//syncTitleLabel.setBounds(SYNC_PANE_X, 10, 145, 23);
		//syncNoteLabel.setBounds(14, 40, 500, 15);
		//syncCheckBox.setBounds(14, 100, 500, 21);
		delayLabel = new JLabel("Delay (in seconds) to wait for the DOM to load:");
		delayTextField = new JTextField(defaultDelay.toString());

		// add to Pane
		add(titleLabel);
		add(driverChooserLabel);
		add(driverChooser);
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
	
	public String getDriverFileName() {
		return driverChooser.getSelectedFile().getAbsolutePath();
    }
    
    public void actionPerformed(ActionEvent e){
        // Handle the select button
		if (e.getSource() == openChooserButton){
			int returnVal = driverChooser.showDialog(this, "Select Driver");
			if (returnVal == JFileChooser.APPROVE_OPTION){
				System.out.println("[FOPO-SRI] Selected " + getDriverFileName() + " as the chrome-driver.");
			}
		}
    }
}