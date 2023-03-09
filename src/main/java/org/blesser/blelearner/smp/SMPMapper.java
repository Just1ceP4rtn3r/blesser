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
                return format.format(record.getMillis()) + " " + record.getSourceClassName() + "\n" + record.getSourceMethodName() + "\n" + record.getLevel() + ": " + " " + record.getMessage() + "\n";
            }
        });
        logble.addHandler(filehandler);
        logble.setUseParentHandlers(false);
    }

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

    public void connectSocket() throws UnknownHostException, IOException {
        socket = new Socket(host, port);
        socket.setTcpNoDelay(true);
        socket.setSoTimeout(RECEIVE_MSG_TIMEOUT);

        output = socket.getOutputStream();
        input = socket.getInputStream();
    }

    //todo:override start method
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

        connectSocket();
    }

    //todo:override reset method
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

        connectSocket();
    }

    //todo:implement concrete packet to string
    public String receiveMessages() throws Exception {
        String out = "";
        return out;
    }

    void sendMessage(byte[] msg) throws Exception {
        output.write(msg);
    }

    //todo:implement BLE packet construction
    public String sendOFHello() throws Exception {
        byte[] msg = new byte[1];
        return receiveMessages();
    }


    //todo:implement string to concrete packet
    public String processSymbol(String input) throws Exception {
        String inAction = input;

        if (!socket.isConnected() || socket.isClosed()) return "ConnectionClosed";
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
