package org.blesser.blelearner.smp;

import org.blesser.blelearner.LearningConfig;

import java.io.IOException;

public class SMPLearningConfig extends LearningConfig {

    String alphabet;
    String target;
    String cmd;
    String host;
    int port;
    boolean restart;
    boolean console_output;
    int timeout;

    public SMPLearningConfig(String filename) throws IOException {
        super(filename);
    }

    public SMPLearningConfig(LearningConfig config) {
        super(config);
    }

    @Override
    public void loadProperties() {
        super.loadProperties();

        if(properties.getProperty("alphabet") != null)
            alphabet = properties.getProperty("alphabet");

        if(properties.getProperty("target").equalsIgnoreCase("controller"))
            target = properties.getProperty("target").toLowerCase();

        if(properties.getProperty("cmd") != null)
            cmd = properties.getProperty("cmd");

        if(properties.getProperty("host") != null)
            host = properties.getProperty("host");

        if(properties.getProperty("port") != null)
            port = Integer.parseInt(properties.getProperty("port"));

        if(properties.getProperty("console_output") != null)
            console_output = Boolean.parseBoolean(properties.getProperty("console_output"));
        else
            console_output = false;

        if(properties.getProperty("restart") != null)
            restart = Boolean.parseBoolean(properties.getProperty("restart"));
        else
            restart = false;

        if(properties.getProperty("timeout") != null)
            timeout = Integer.parseInt(properties.getProperty("timeout"));


    }


}
