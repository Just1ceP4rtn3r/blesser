package org.blesser.blelearner.smp;

import org.projectfloodlight.openflow.protocol.OFFactories;
import org.projectfloodlight.openflow.protocol.OFFactory;
import org.projectfloodlight.openflow.protocol.OFHello;
import org.projectfloodlight.openflow.protocol.OFVersion;

import java.io.*;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.*;

public class SMPMapper {
    // Timeout in ms
    int RECEIVE_MSG_TIMEOUT = 100;
    // Restart server after every session
    boolean REQUIRE_RESTART = false;
    // Send output from TLS implementation to console
    boolean CONSOLE_OUTPUT = false;
    static Logger logble = Logger.getLogger("ble.log");
    FileHandler filehandler;
    InputStream is = null;
    BufferedReader br = null;
    String result = null;
    String type = null;
    String outAction;
    String host = "192.168.239.128";
    int port = 6653;

    // controller connection related
    Socket socket;
    OutputStream output;
    InputStream input;
    // Timeout in ms

    String cmd;
    Process targetProcess;

    public void initLog() {
        try {
            filehandler = new FileHandler("output_ble\\logble.log");
        } catch (SecurityException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        filehandler.setLevel(Level.INFO);
        filehandler.setFormatter(new Formatter() {
            SimpleDateFormat format = new SimpleDateFormat("YYYY-MM-dd HH:MM:ss S");

            public String format(LogRecord record) {
                return format.format(record.getMillis()) + " " + record.getSourceClassName() + "\n"
                        + record.getSourceMethodName() + "\n" + record.getLevel() + ": " + " " + record.getMessage()
                        + "\n";
            }
        });
        logble.addHandler(filehandler);
        logble.setUseParentHandlers(false);
    }

    /*
     * Author: syncxxx
     * Date: 2023-3-29
     * Description: init serial connection
     * Input: none
     * Output: none
     */
    // TODO: UART or other serial port connection
    public void initSerialConnection() throws UnknownHostException, IOException {
        socket = new Socket(host, port);
        socket.setTcpNoDelay(true);
        socket.setSoTimeout(RECEIVE_MSG_TIMEOUT);

        output = socket.getOutputStream();
        input = socket.getInputStream();
    }

    /********************************************************************************
     * Paramemters setting
     ********************************************************************************/

    public void setHost(String host) {
        this.host = host;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public void setCommand(String cmd) {
        this.cmd = cmd;
    }

    public void setRequireRestart(boolean restart) {
        this.REQUIRE_RESTART = restart;
    }

    /********************************************************************************
     * Message constructions
     * 0x01 Pairing Request LE-U, ACL-U
     * 0x02 Pairing Response LE-U, ACL-U
     * 0x03 Pairing Confirm LE-U
     * 0x04 Pairing Random LE-U
     * 0x05 Pairing Failed LE-U, ACL-U
     * 0x06 Encryption Information LE-U
     * 0x07 Central Identification LE-U
     * 0x08 Identity Information LE-U, ACL-U
     * 0x09 Identity Address Information LE-U, ACL-U
     * 0x0A Signing Information LE-U, ACL-U
     * 0x0B Security Request LE-U
     * 0x0C Pairing Public Key LE-U
     * 0x0D Pairing DHKey Check LE-U
     * 0x0E Pairing Keypress Notification LE-U
     ********************************************************************************/

    // todo:implement concrete packet to string
    public String receiveMessages() throws Exception {
        String out = "";
        return out;
    }

    void sendMessage(byte[] msg) throws Exception {
        output.write(msg);
    }

    /*
     * Description: send pairing request
     * Input: fileds =
     * "IOCap:0x05-OOBflag:0x00-AUTHReq:0x01-InitKeyDist:0x07-RespKeyDist:0x07"
     * Output: none
     */
    public String sendPairingReq(String fields) throws Exception {
        String[] fields_str = fields.split("-");
        Map<String, Object> fileds_map = new HashMap<>();
        for (String s : fields_str) {
            String[] split1 = s.split(":");
            String key = split1[0];
            String value = split1[1];
            fileds_map.put(key, value);
            // switch (key) {
            // case "IOCap":
            // break;
            // case "OOBflag":
            // break;
            // case "AUTHReq":
            // break;
            // case "InitKeyDist":
            // break;
            // case "RespKeyDist":
            // break;
            // default:
            // break;
            // }
        }

        return receiveMessages();
    }

    public String sendPairingRes(String fileds) throws Exception {

        byte[] msg = new byte[1];
        return receiveMessages();
    }

    public String sendPairingConfirm(String fileds) throws Exception {

        byte[] msg = new byte[1];
        return receiveMessages();
    }

    public String sendPairingRandom(String fileds) throws Exception {

        byte[] msg = new byte[1];
        return receiveMessages();
    }

    public String sendPairingFailed(String fileds) throws Exception {

        byte[] msg = new byte[1];
        return receiveMessages();
    }

    public String sendEncryptionInfo(String fileds) throws Exception {

        byte[] msg = new byte[1];
        return receiveMessages();
    }

    /********************************************************************************
     * Init and reset
     ********************************************************************************/

    // todo:override start method
    public void start() throws Exception {
        if (cmd != null && !cmd.equals("")) {
            System.out.println(Arrays.toString(cmd.split(" ")));
            ProcessBuilder pb = new ProcessBuilder(cmd.split(" "));

            if (CONSOLE_OUTPUT) {
                pb.inheritIO();
            } else {
                pb.redirectErrorStream(true);
                pb.redirectOutput(new File("output.log"));
            }
            targetProcess = pb.start();

            Thread.sleep(5000);
        }

        initSerialConnection();
    }

    // todo:override reset method
    public void reset() throws Exception {
        socket.close();
        if (REQUIRE_RESTART && cmd != null && !cmd.equals("")) {

            targetProcess.destroy();

            Thread.sleep(500);

            ProcessBuilder pb = new ProcessBuilder(cmd.split(" "));

            if (CONSOLE_OUTPUT) {
                pb.inheritIO();
            } else {
                pb.redirectErrorStream(true);
                pb.redirectOutput(new File("output.log"));
            }

            targetProcess = pb.start();

            Thread.sleep(200);
        }

        initSerialConnection();
    }

    /********************************************************************************
     * Process input symbol
     ********************************************************************************/

    // todo:implement string to concrete packet
    public String processSymbol(String input) throws Exception {
        String inAction = input;

        if (!socket.isConnected() || socket.isClosed())
            return "ConnectionClosed";
        try {
            if (inAction.equals("HELLO")) {
                return sendOFHello();
            } else {
                System.out.println("Unknown input symbol (" + inAction + ")...");
                throw new RuntimeException("Unknown input Symbol (" + inAction + ")...");
            }
        } catch (SocketException e) {
            String outAction = "ConnectionClosed";
            return outAction;
        }

    }

}
