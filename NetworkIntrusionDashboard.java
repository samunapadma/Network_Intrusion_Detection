import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.io.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class NetworkIntrusionDashboard extends JFrame {

    // ==========================================
    // CONFIGURATION
    // ==========================================

    private static final int PORT_SCAN_THRESHOLD = 5;
    private static final int MONITORING_TIME = 60;
    private static final int CHECK_INTERVAL = 2000;

    private static final String LOG_FILE =
            "security_log.txt";

    private static final DateTimeFormatter FORMATTER =
            DateTimeFormatter.ofPattern(
                    "yyyy-MM-dd HH:mm:ss"
            );


    // ==========================================
    // DATA
    // ==========================================

    private final Map<String, Set<Integer>> ipPorts =
            new HashMap<>();

    private final Set<String> alertedIPs =
            new HashSet<>();

    private final Set<String> displayedConnections =
            new HashSet<>();


    // ==========================================
    // GUI COMPONENTS
    // ==========================================

    private JTextArea outputArea;

    private JLabel statusLabel;

    private JLabel connectionLabel;

    private JLabel alertLabel;

    private JButton startButton;

    private JButton simulationButton;

    private JButton logButton;

    private JButton clearButton;


    // ==========================================
    // CONSTRUCTOR
    // ==========================================

    public NetworkIntrusionDashboard() {

        createLogFile();

        setTitle(
                "Network Intrusion Detection System"
        );

        setSize(1050, 650);

        setLocationRelativeTo(null);

        setDefaultCloseOperation(
                JFrame.EXIT_ON_CLOSE
        );

        setLayout(
                new BorderLayout()
        );

        createGUI();
    }


    // ==========================================
    // CREATE GUI
    // ==========================================

    private void createGUI() {

        // ======================================
        // TOP HEADER
        // ======================================

        JPanel headerPanel =
                new JPanel(
                        new BorderLayout()
                );

        headerPanel.setBorder(
                new EmptyBorder(
                        15, 20, 15, 20
                )
        );


        JLabel titleLabel =
                new JLabel(
                        "NETWORK INTRUSION DETECTION SYSTEM"
                );

        titleLabel.setFont(
                new Font(
                        "Arial",
                        Font.BOLD,
                        25
                )
        );


        JLabel subtitleLabel =
                new JLabel(
                        "Java-Based Network Security Monitoring"
                );

        subtitleLabel.setFont(
                new Font(
                        "Arial",
                        Font.PLAIN,
                        14
                )
        );


        JPanel titlePanel =
                new JPanel(
                        new GridLayout(
                                2, 1
                        )
                );

        titlePanel.add(
                titleLabel
        );

        titlePanel.add(
                subtitleLabel
        );


        headerPanel.add(
                titlePanel,
                BorderLayout.WEST
        );


        statusLabel =
                new JLabel(
                        "● SYSTEM READY"
                );

        statusLabel.setFont(
                new Font(
                        "Arial",
                        Font.BOLD,
                        15
                )
        );


        headerPanel.add(
                statusLabel,
                BorderLayout.EAST
        );


        add(
                headerPanel,
                BorderLayout.NORTH
        );


        // ======================================
        // CENTER
        // ======================================

        JPanel centerPanel =
                new JPanel(
                        new BorderLayout(
                                10, 10
                        )
                );

        centerPanel.setBorder(
                new EmptyBorder(
                        10, 20, 10, 20
                )
        );


        // ======================================
        // CONTROL PANEL
        // ======================================

        JPanel controlPanel =
                new JPanel(
                        new GridLayout(
                                1, 4, 10, 10
                        )
                );


        startButton =
                new JButton(
                        "▶ Start Monitoring"
                );

        simulationButton =
                new JButton(
                        "🧪 Safe Simulation"
                );

        logButton =
                new JButton(
                        "📄 View Security Log"
                );

        clearButton =
                new JButton(
                        "🧹 Clear Output"
                );


        controlPanel.add(
                startButton
        );

        controlPanel.add(
                simulationButton
        );

        controlPanel.add(
                logButton
        );

        controlPanel.add(
                clearButton
        );


        centerPanel.add(
                controlPanel,
                BorderLayout.NORTH
        );


        // ======================================
        // OUTPUT AREA
        // ======================================

        outputArea =
                new JTextArea();

        outputArea.setEditable(
                false
        );

        outputArea.setFont(
                new Font(
                        "Consolas",
                        Font.PLAIN,
                        14
                )
        );

        outputArea.setLineWrap(
                true
        );

        outputArea.setWrapStyleWord(
                true
        );


        JScrollPane scrollPane =
                new JScrollPane(
                        outputArea
                );


        centerPanel.add(
                scrollPane,
                BorderLayout.CENTER
        );


        add(
                centerPanel,
                BorderLayout.CENTER
        );


        // ======================================
        // BOTTOM STATUS PANEL
        // ======================================

        JPanel bottomPanel =
                new JPanel(
                        new GridLayout(
                                1, 3
                        )
                );


        connectionLabel =
                new JLabel(
                        "Connections: 0",
                        SwingConstants.CENTER
                );


        alertLabel =
                new JLabel(
                        "Security Alerts: 0",
                        SwingConstants.CENTER
                );


        JLabel logLabel =
                new JLabel(
                        "Log: security_log.txt",
                        SwingConstants.CENTER
                );


        bottomPanel.add(
                connectionLabel
        );

        bottomPanel.add(
                alertLabel
        );

        bottomPanel.add(
                logLabel
        );


        add(
                bottomPanel,
                BorderLayout.SOUTH
        );


        // ======================================
        // BUTTON EVENTS
        // ======================================

        startButton.addActionListener(
                e -> startMonitoring()
        );


        simulationButton.addActionListener(
                e -> runSafeSimulation()
        );


        logButton.addActionListener(
                e -> viewSecurityLog()
        );


        clearButton.addActionListener(
                e -> outputArea.setText("")
        );


        appendOutput(
                "============================================\n"
        );

        appendOutput(
                " NETWORK INTRUSION DETECTION SYSTEM\n"
        );

        appendOutput(
                "============================================\n\n"
        );

        appendOutput(
                "[INFO] System initialized successfully.\n"
        );

        appendOutput(
                "[INFO] Select an operation from the buttons above.\n\n"
        );
    }


    // ==========================================
    // START MONITORING
    // ==========================================

    private void startMonitoring() {

        startButton.setEnabled(
                false
        );

        simulationButton.setEnabled(
                false
        );


        statusLabel.setText(
                "● MONITORING"
        );


        appendOutput(
                "\n============================================\n"
        );

        appendOutput(
                "REAL NETWORK MONITORING STARTED\n"
        );

        appendOutput(
                "============================================\n"
        );


        ipPorts.clear();

        alertedIPs.clear();

        displayedConnections.clear();


        Thread monitoringThread =
                new Thread(
                        () -> {

                            long endTime =
                                    System.currentTimeMillis()
                                            + MONITORING_TIME
                                            * 1000L;


                            while (
                                    System.currentTimeMillis()
                                            < endTime
                            ) {

                                try {

                                    monitorConnections();

                                    Thread.sleep(
                                            CHECK_INTERVAL
                                    );

                                } catch (
                                        Exception ex
                                ) {

                                    appendOutput(
                                            "\n[ERROR] "
                                                    + ex.getMessage()
                                                    + "\n"
                                    );

                                    break;
                                }
                            }


                            SwingUtilities.invokeLater(
                                    () -> {

                                        statusLabel.setText(
                                                "● SYSTEM READY"
                                        );

                                        startButton.setEnabled(
                                                true
                                        );

                                        simulationButton.setEnabled(
                                                true
                                        );

                                        appendOutput(
                                                "\n============================================\n"
                                        );

                                        appendOutput(
                                                "MONITORING COMPLETED\n"
                                        );

                                        appendOutput(
                                                "============================================\n"
                                        );

                                        appendOutput(
                                                "Remote IPs: "
                                                        + ipPorts.size()
                                                        + "\n"
                                        );

                                        appendOutput(
                                                "Connections: "
                                                        + displayedConnections.size()
                                                        + "\n"
                                        );

                                        appendOutput(
                                                "Security Alerts: "
                                                        + alertedIPs.size()
                                                        + "\n"
                                        );
                                    }
                            );
                        }
                );


        monitoringThread.start();
    }


    // ==========================================
    // NETSTAT MONITORING
    // ==========================================

    private void monitorConnections()
            throws IOException {

        ProcessBuilder builder =
                new ProcessBuilder(
                        "netstat",
                        "-ano",
                        "-p",
                        "tcp"
                );

        builder.redirectErrorStream(
                true
        );


        Process process =
                builder.start();


        try (
                BufferedReader reader =
                        new BufferedReader(
                                new InputStreamReader(
                                        process.getInputStream()
                                )
                        )
        ) {

            String line;

            while (
                    (line = reader.readLine())
                            != null
            ) {

                analyzeConnection(line);
            }
        }
    }


    // ==========================================
    // ANALYZE CONNECTION
    // ==========================================

    private void analyzeConnection(
            String line
    ) {

        String data =
                line.trim();


        if (!data.startsWith("TCP")) {

            return;
        }


        String[] parts =
                data.split("\\s+");


        if (parts.length < 5) {

            return;
        }


        String localAddress =
                parts[1];

        String remoteAddress =
                parts[2];

        String state =
                parts[3];


        String remoteIP =
                extractIP(
                        remoteAddress
                );


        int localPort =
                extractPort(
                        localAddress
                );


        if (
                remoteIP == null
                        || localPort == -1
        ) {

            return;
        }


        if (
                isLocalAddress(
                        remoteIP
                )
        ) {

            return;
        }


        String connectionID =
                remoteIP
                        + ":"
                        + localPort
                        + ":"
                        + state;


        if (
                !displayedConnections
                        .contains(
                                connectionID
                        )
        ) {

            displayedConnections.add(
                    connectionID
            );


            appendOutput(
                    "\n[CONNECTION DETECTED]\n"
            );

            appendOutput(
                    "Remote IP       : "
                            + remoteIP
                            + "\n"
            );

            appendOutput(
                    "Local Port      : "
                            + localPort
                            + "\n"
            );

            appendOutput(
                    "Protocol        : TCP\n"
            );

            appendOutput(
                    "State           : "
                            + state
                            + "\n"
            );


            updateConnectionCount();
        }


        Set<Integer> ports =
                ipPorts.computeIfAbsent(
                        remoteIP,
                        k -> new HashSet<>()
                );


        ports.add(
                localPort
        );


        if (
                ports.size()
                        >= PORT_SCAN_THRESHOLD

                        && !alertedIPs
                        .contains(
                                remoteIP
                        )
        ) {

            generateAlert(
                    remoteIP,
                    ports,
                    false
            );
        }
    }


    // ==========================================
    // SAFE SIMULATION
    // ==========================================

    private void runSafeSimulation() {

        appendOutput(
                "\n============================================\n"
        );

        appendOutput(
                "SAFE PORT SCAN SIMULATION\n"
        );

        appendOutput(
                "============================================\n"
        );

        appendOutput(
                "[INFO] Simulation mode only.\n"
        );

        appendOutput(
                "[INFO] No external computer is scanned.\n\n"
        );


        String testIP =
                "127.0.0.1";


        Set<Integer> testPorts =
                new LinkedHashSet<>();


        testPorts.add(22);

        testPorts.add(80);

        testPorts.add(443);

        testPorts.add(8080);

        testPorts.add(3306);


        appendOutput(
                "[SIMULATION] Source IP: "
                        + testIP
                        + "\n"
        );


        appendOutput(
                "[SIMULATION] Ports: "
                        + testPorts
                        + "\n"
        );


        appendOutput(
                "[SIMULATION] "
                        + testPorts.size()
                        + " different ports detected.\n"
        );


        generateAlert(
                testIP,
                testPorts,
                true
        );


        appendOutput(
                "\n[SIMULATION COMPLETED]\n"
        );

        appendOutput(
                "[INFO] No real port scan was performed.\n"
        );
    }


    // ==========================================
    // GENERATE ALERT
    // ==========================================

    private void generateAlert(
            String ip,
            Set<Integer> ports,
            boolean simulation
    ) {

        alertedIPs.add(
                ip
        );


        appendOutput(
                "\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
        );

        appendOutput(
                "           SECURITY ALERT\n"
        );

        appendOutput(
                "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
        );

        appendOutput(
                "Possible Port Scanning Detected!\n"
        );

        appendOutput(
                "Source IP       : "
                        + ip
                        + "\n"
        );

        appendOutput(
                "Ports Detected  : "
                        + ports
                        + "\n"
        );

        appendOutput(
                "Number of Ports : "
                        + ports.size()
                        + "\n"
        );


        if (simulation) {

            appendOutput(
                    "Detection Type  : SAFE SIMULATION\n"
            );
        } else {

            appendOutput(
                    "Detection Type  : NETWORK MONITORING\n"
            );
        }


        appendOutput(
                "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
        );


        updateAlertCount();


        String prefix =
                simulation
                        ? "SIMULATED Port Scan"
                        : "Possible Port Scan";


        writeSecurityLog(
                prefix
                        + " | Source IP: "
                        + ip
                        + " | Ports: "
                        + ports
        );
    }


    // ==========================================
    // WRITE LOG
    // ==========================================

    private void writeSecurityLog(
            String message
    ) {

        String time =
                LocalDateTime.now()
                        .format(
                                FORMATTER
                        );


        try (
                FileWriter writer =
                        new FileWriter(
                                LOG_FILE,
                                true
                        )
        ) {

            writer.write(
                    "["
                            + time
                            + "] "
                            + message
                            + System.lineSeparator()
            );


            appendOutput(
                    "[LOG] Alert saved to "
                            + LOG_FILE
                            + "\n"
            );

        } catch (
                IOException e
        ) {

            appendOutput(
                    "[ERROR] Could not write log.\n"
            );
        }
    }


    // ==========================================
    // VIEW LOG
    // ==========================================

    private void viewSecurityLog() {

        appendOutput(
                "\n============================================\n"
        );

        appendOutput(
                "SECURITY LOG\n"
        );

        appendOutput(
                "============================================\n"
        );


        File file =
                new File(
                        LOG_FILE
                );


        if (!file.exists()) {

            appendOutput(
                    "[INFO] No log file found.\n"
            );

            return;
        }


        try (
                BufferedReader reader =
                        new BufferedReader(
                                new FileReader(
                                        file
                                )
                        )
        ) {

            String line;

            while (
                    (line = reader.readLine())
                            != null
            ) {

                appendOutput(
                        line
                                + "\n"
                );
            }

        } catch (
                IOException e
        ) {

            appendOutput(
                    "[ERROR] Unable to read log file.\n"
            );
        }


        appendOutput(
                "============================================\n"
        );
    }


    // ==========================================
    // CREATE LOG FILE
    // ==========================================

    private void createLogFile() {

        File file =
                new File(
                        LOG_FILE
                );


        if (file.exists()) {

            return;
        }


        try (
                FileWriter writer =
                        new FileWriter(
                                LOG_FILE,
                                true
                        )
        ) {

            String time =
                    LocalDateTime.now()
                            .format(
                                    FORMATTER
                            );


            writer.write(
                    "========================================"
                            + System.lineSeparator()
            );

            writer.write(
                    "NETWORK INTRUSION DETECTION LOG"
                            + System.lineSeparator()
            );

            writer.write(
                    "Created: "
                            + time
                            + System.lineSeparator()
            );

            writer.write(
                    "========================================"
                            + System.lineSeparator()
            );

        } catch (
                IOException e
        ) {
            // Ignore
        }
    }


    // ==========================================
    // EXTRACT IP
    // ==========================================

    private String extractIP(
            String address
    ) {

        try {

            if (
                    address.startsWith("[")
            ) {

                int end =
                        address.lastIndexOf(
                                ']'
                        );


                if (end > 0) {

                    return address.substring(
                            1,
                            end
                    );
                }
            }


            int colon =
                    address.lastIndexOf(
                            ':'
                    );


            if (colon > 0) {

                return address.substring(
                        0,
                        colon
                );
            }

        } catch (
                Exception e
        ) {

            return null;
        }


        return null;
    }


    // ==========================================
    // EXTRACT PORT
    // ==========================================

    private int extractPort(
            String address
    ) {

        try {

            if (
                    address.startsWith("[")
            ) {

                int end =
                        address.lastIndexOf(
                                ']'
                        );


                if (
                        end >= 0
                                && address.length()
                                > end + 2
                ) {

                    return Integer.parseInt(
                            address.substring(
                                    end + 2
                            )
                    );
                }
            }


            int colon =
                    address.lastIndexOf(
                            ':'
                    );


            if (colon >= 0) {

                return Integer.parseInt(
                        address.substring(
                                colon + 1
                        )
                );
            }

        } catch (
                NumberFormatException e
        ) {

            return -1;
        }


        return -1;
    }


    // ==========================================
    // CHECK LOCAL ADDRESS
    // ==========================================

    private boolean isLocalAddress(
            String ip
    ) {

        return ip.equals(
                "127.0.0.1"
        )
                || ip.equals(
                "0.0.0.0"
        )
                || ip.equals(
                "::1"
        )
                || ip.equalsIgnoreCase(
                "localhost"
        );
    }


    // ==========================================
    // UPDATE COUNTERS
    // ==========================================

    private void updateConnectionCount() {

        SwingUtilities.invokeLater(
                () -> connectionLabel.setText(
                        "Connections: "
                                + displayedConnections.size()
                )
        );
    }


    private void updateAlertCount() {

        SwingUtilities.invokeLater(
                () -> alertLabel.setText(
                        "Security Alerts: "
                                + alertedIPs.size()
                )
        );
    }


    // ==========================================
    // APPEND OUTPUT SAFELY
    // ==========================================

    private void appendOutput(
            String text
    ) {

        SwingUtilities.invokeLater(
                () -> {

                    outputArea.append(
                            text
                    );

                    outputArea.setCaretPosition(
                            outputArea.getDocument()
                                    .getLength()
                    );
                }
        );
    }


    // ==========================================
    // MAIN
    // ==========================================

    public static void main(
            String[] args
    ) {

        SwingUtilities.invokeLater(
                () -> {

                    NetworkIntrusionDashboard app =
                            new NetworkIntrusionDashboard();

                    app.setVisible(
                            true
                    );
                }
        );
    }
}