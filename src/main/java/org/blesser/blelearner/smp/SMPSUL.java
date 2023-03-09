package org.blesser.blelearner.smp;

import net.automatalib.words.impl.SimpleAlphabet;
import org.blesser.blelearner.StateLearnerSUL;

import java.util.Arrays;

public class SMPSUL implements StateLearnerSUL<String,String>{
    SimpleAlphabet<String> alphabet;
    SMPMapper smpMapper;
    public SMPSUL(SMPLearningConfig config) throws Exception {
        alphabet = new SimpleAlphabet<String>(Arrays.asList(config.alphabet.split(" ")));

        smpMapper = new SMPMapper();


        smpMapper.setHost(config.host);
        smpMapper.setPort(config.port);
        smpMapper.setCommand(config.cmd);
        smpMapper.setRequireRestart(config.restart);

        smpMapper.start();
    }

    public SimpleAlphabet<String> getAlphabet() {
        return alphabet;
    }

    @Override
    public String step(String symbol) {
        String result = null;
        try {
            result = smpMapper.processSymbol(symbol);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    @Override
    public void pre() {
        try {
            smpMapper.reset();
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }


    @Override
    public void post() {
    }
}
