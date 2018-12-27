package burp;

import org.focalpoint.isns.burp.srichecks.SRIBurpExtension;

public class BurpExtender implements IBurpExtender{

    SRIBurpExtension sribe = new SRIBurpExtension();

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        sribe.registerExtenderCallbacks(callbacks);
    }
}
