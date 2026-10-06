import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;

public class NetworkIntrusionDetection {

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
    // DATA STRUCTURES
    // ==========================================

    // Stores different ports for each remote IP
    private static final Map<String, Set<Integer>> ipPorts =
            new HashMap<>();

    // Stores IP addresses for which an alert was generated
    private static final Set<String> alertedIPs =
            new HashSet<>();

    // Prevents repeated display of same connection
    private static final Set<String> displayedConnections =
            new HashSet<>();


    // ==========================================
    // SCANNER
    // ==========================================

    private static final Scanner scanner =
            new Scanner(System.in);


    // ==========================================
    // MAIN METHOD
    // ==========================================

    public static void main(String[] args) {

        // Create log file when program starts
        createLogFile();

        boolean running = true;

        while (running) {

            printMenu();

            System.out.print(
                    "Enter your choice: "
            );

            String choice =
                    scanner.nextLine().trim();

            switch (choice) {

                case "1":
                    startNetworkMonitoring();
                    break;

                case "2":
                    runSafeSimulation();
                    break;

                case "3":
                    viewSecurityLog();
                    break;

                case "4":
                    running = false;

                    System.out.println();
                    System.out.println(
                            "========================================"
                    );

                    System.out.println(
                            "Thank you for using Network IDS."
                    );

                    System.out.println(
                            "Program terminated safely."
                    );

                    System.out.println(
                            "========================================"
                    );

                    break;

                default:
                    System.out.println();
                    System.out.println(
                            "[ERROR] Invalid choice."
                    );

                    System.out.println(
                            "Please enter 1, 2, 3, or 4."
                    );

                    System.out.println();
            }
        }

        scanner.close();
    }


    // ==========================================
    // MAIN MENU
    // ==========================================

    private static void printMenu() {

        System.out.println();

        System.out.println(
                "=============================================="
        );

        System.out.println(
                "       NETWORK INTRUSION DETECTION SYSTEM"
        );

        System.out.println(
                "=============================================="
        );

        System.out.println(
                "1. Start Network Monitoring"
        );

        System.out.println(
                "2. Run Safe Port Scan Simulation"
        );

        System.out.println(
                "3. View Security Log"
        );

        System.out.println(
                "4. Exit"
        );

        System.out.println(
                "=============================================="
        );
    }


    // ==========================================
    // CREATE LOG FILE
    // ==========================================

    private static void createLogFile() {

        File file =
                new File(LOG_FILE);

        // If file already exists, don't recreate it
        if (file.exists()) {

            return;
        }

        try {

            String time =
                    LocalDateTime.now()
                            .format(FORMATTER);

            try (FileWriter writer =
                         new FileWriter(
                                 LOG_FILE,
                                 true
                         )) {

                writer.write(
                        "========================================"
                                + System.lineSeparator()
                );

                writer.write(
                        "NETWORK INTRUSION DETECTION LOG"
                                + System.lineSeparator()
                );

                writer.write(
                        "Log Created: "
                                + time
                                + System.lineSeparator()
                );

                writer.write(
                        "========================================"
                                + System.lineSeparator()
                );
            }

            System.out.println(
                    "[INFO] Security log file created."
            );

        } catch (IOException e) {

            System.out.println(
                    "[ERROR] Unable to create log file."
            );

            System.out.println(
                    "Reason: " + e.getMessage()
            );
        }
    }


    // ==========================================
    // REAL NETWORK MONITORING
    // ==========================================

    private static void startNetworkMonitoring() {

        System.out.println();

        System.out.println(
                "=============================================="
        );

        System.out.println(
                "          REAL NETWORK MONITORING"
        );

        System.out.println(
                "=============================================="
        );

        System.out.println(
                "Monitoring time: "
                        + MONITORING_TIME
                        + " seconds"
        );

        System.out.println(
                "Detection threshold: "
                        + PORT_SCAN_THRESHOLD
                        + " different ports"
        );

        System.out.println(
                "----------------------------------------------"
        );

        System.out.println(
                "[INFO] Monitoring started..."
        );


        // Clear old monitoring data
        ipPorts.clear();
        alertedIPs.clear();
        displayedConnections.clear();


        long endTime =
                System.currentTimeMillis()
                        + MONITORING_TIME * 1000L;


        while (
                System.currentTimeMillis()
                        < endTime
        ) {

            try {

                monitorConnections();

                Thread.sleep(
                        CHECK_INTERVAL
                );

            } catch (IOException e) {

                System.out.println();

                System.out.println(
                        "[ERROR] Unable to read network connections."
                );

                System.out.println(
                        "Reason: "
                                + e.getMessage()
                );

                break;

            } catch (InterruptedException e) {

                Thread.currentThread().interrupt();

                System.out.println(
                        "[ERROR] Monitoring interrupted."
                );

                break;
            }
        }


        printMonitoringSummary();
    }


    // ==========================================
    // RUN NETSTAT
    // ==========================================

    private static void monitorConnections()
            throws IOException {

        ProcessBuilder processBuilder =
                new ProcessBuilder(
                        "netstat",
                        "-ano",
                        "-p",
                        "tcp"
                );

        processBuilder.redirectErrorStream(
                true
        );

        Process process =
                processBuilder.start();


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


        try {

            process.waitFor();

        } catch (InterruptedException e) {

            Thread.currentThread().interrupt();

            throw new IOException(
                    "Network monitoring interrupted."
            );
        }
    }


    // ==========================================
    // ANALYZE CONNECTION
    // ==========================================

    private static void analyzeConnection(
            String line
    ) {

        String data =
                line.trim();


        // Process only TCP lines
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

        String foreignAddress =
                parts[2];

        String state =
                parts[3];


        String remoteIP =
                extractIP(foreignAddress);


        int localPort =
                extractPort(localAddress);


        if (
                remoteIP == null
                        || localPort == -1
        ) {

            return;
        }


        // Ignore local connections
        if (isLocalAddress(remoteIP)) {

            return;
        }


        // Create connection identifier
        String connectionID =
                remoteIP
                        + ":"
                        + localPort
                        + ":"
                        + state;


        // Display only once
        if (
                !displayedConnections
                        .contains(connectionID)
        ) {

            displayedConnections.add(
                    connectionID
            );


            System.out.println();

            System.out.println(
                    "[CONNECTION DETECTED]"
            );

            System.out.println(
                    "Remote IP       : "
                            + remoteIP
            );

            System.out.println(
                    "Local Port      : "
                            + localPort
            );

            System.out.println(
                    "Protocol        : TCP"
            );

            System.out.println(
                    "Connection State: "
                            + state
            );
        }


        // Store port for this remote IP
        Set<Integer> ports =
                ipPorts.computeIfAbsent(
                        remoteIP,
                        key -> new HashSet<>()
                );


        ports.add(
                localPort
        );


        // Check port scan condition
        detectPortScan(
                remoteIP,
                ports
        );
    }


    // ==========================================
    // PORT SCAN DETECTION
    // ==========================================

    private static void detectPortScan(
            String remoteIP,
            Set<Integer> ports
    ) {

        if (
                ports.size()
                        >= PORT_SCAN_THRESHOLD

                        && !alertedIPs
                        .contains(remoteIP)
        ) {

            alertedIPs.add(
                    remoteIP
            );


            String message =
                    "Possible Port Scan | "
                            + "Source IP: "
                            + remoteIP
                            + " | Ports: "
                            + ports;


            displaySecurityAlert(
                    remoteIP,
                    ports
            );


            writeSecurityLog(
                    message
            );
        }
    }


    // ==========================================
    // SAFE PORT SCAN SIMULATION
    // ==========================================

    private static void runSafeSimulation() {

        System.out.println();

        System.out.println(
                "=============================================="
        );

        System.out.println(
                "          SAFE PORT SCAN SIMULATION"
        );

        System.out.println(
                "=============================================="
        );

        System.out.println(
                "[INFO] Simulation mode only."
        );

        System.out.println(
                "[INFO] No external computer will be scanned."
        );

        System.out.println();


        // Local test IP
        String simulatedIP =
                "127.0.0.1";


        // Simulated ports
        Set<Integer> simulatedPorts =
                new HashSet<>();

        simulatedPorts.add(22);
        simulatedPorts.add(80);
        simulatedPorts.add(443);
        simulatedPorts.add(8080);
        simulatedPorts.add(3306);


        System.out.println(
                "[SIMULATION] Analyzing test activity..."
        );

        System.out.println(
                "[SIMULATION] Source IP: "
                        + simulatedIP
        );

        System.out.println(
                "[SIMULATION] Ports: "
                        + simulatedPorts
        );


        System.out.println();

        System.out.println(
                "[SIMULATION] "
                        + simulatedPorts.size()
                        + " different ports detected."
        );


        // Generate safe simulated alert
        displaySecurityAlert(
                simulatedIP,
                simulatedPorts
        );


        String message =
                "SIMULATED Port Scan | "
                        + "Source IP: "
                        + simulatedIP
                        + " | Ports: "
                        + simulatedPorts;


        writeSecurityLog(
                message
        );


        System.out.println();

        System.out.println(
                "[SIMULATION COMPLETED]"
        );

        System.out.println(
                "No real port scan was performed."
        );

        System.out.println(
                "The event was recorded for demonstration."
        );
    }


    // ==========================================
    // DISPLAY SECURITY ALERT
    // ==========================================

    private static void displaySecurityAlert(
            String ip,
            Set<Integer> ports
    ) {

        System.out.println();

        System.out.println(
                "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        );

        System.out.println(
                "              SECURITY ALERT"
        );

        System.out.println(
                "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        );

        System.out.println(
                "Possible Port Scanning Detected!"
        );

        System.out.println(
                "Source IP       : "
                        + ip
        );

        System.out.println(
                "Ports Detected  : "
                        + ports
        );

        System.out.println(
                "Number of Ports : "
                        + ports.size()
        );

        System.out.println(
                "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        );

        System.out.println();
    }


    // ==========================================
    // WRITE SECURITY LOG
    // ==========================================

    private static void writeSecurityLog(
            String message
    ) {

        String time =
                LocalDateTime.now()
                        .format(FORMATTER);


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


            System.out.println(
                    "[LOG] Security alert saved to "
                            + LOG_FILE
            );

        } catch (IOException e) {

            System.out.println(
                    "[ERROR] Could not write security log."
            );

            System.out.println(
                    "Reason: "
                            + e.getMessage()
            );
        }
    }


    // ==========================================
    // VIEW SECURITY LOG
    // ==========================================

    private static void viewSecurityLog() {

        System.out.println();

        System.out.println(
                "=============================================="
        );

        System.out.println(
                "               SECURITY LOG"
        );

        System.out.println(
                "=============================================="
        );


        File file =
                new File(LOG_FILE);


        if (!file.exists()) {

            System.out.println(
                    "[INFO] No security log file found."
            );

            System.out.println(
                    "=============================================="
            );

            return;
        }


        try (
                BufferedReader reader =
                        new BufferedReader(
                                new FileReader(
                                        LOG_FILE
                                )
                        )
        ) {

            String line;

            boolean hasContent =
                    false;


            while (
                    (line = reader.readLine())
                            != null
            ) {

                System.out.println(
                        line
                );

                hasContent =
                        true;
            }


            if (!hasContent) {

                System.out.println(
                        "[INFO] Security log is empty."
                );
            }

        } catch (IOException e) {

            System.out.println(
                    "[ERROR] Unable to read security log."
            );

            System.out.println(
                    "Reason: "
                            + e.getMessage()
            );
        }


        System.out.println(
                "=============================================="
        );
    }


    // ==========================================
    // EXTRACT IP ADDRESS
    // ==========================================

    private static String extractIP(
            String address
    ) {

        try {

            // IPv6
            if (
                    address.startsWith("[")
            ) {

                int closingBracket =
                        address.lastIndexOf(']');


                if (
                        closingBracket > 0
                ) {

                    return address.substring(
                            1,
                            closingBracket
                    );
                }
            }


            // IPv4
            int colon =
                    address.lastIndexOf(':');


            if (colon > 0) {

                return address.substring(
                        0,
                        colon
                );
            }

        } catch (Exception e) {

            return null;
        }


        return null;
    }


    // ==========================================
    // EXTRACT PORT
    // ==========================================

    private static int extractPort(
            String address
    ) {

        try {

            // IPv6
            if (
                    address.startsWith("[")
            ) {

                int closingBracket =
                        address.lastIndexOf(']');


                if (
                        closingBracket >= 0
                                && address.length()
                                > closingBracket + 2
                ) {

                    return Integer.parseInt(
                            address.substring(
                                    closingBracket + 2
                            )
                    );
                }
            }


            // IPv4
            int colon =
                    address.lastIndexOf(':');


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

    private static boolean isLocalAddress(
            String ip
    ) {

        return ip.equals("127.0.0.1")
                || ip.equals("0.0.0.0")
                || ip.equals("::1")
                || ip.equalsIgnoreCase(
                        "localhost"
                );
    }


    // ==========================================
    // MONITORING SUMMARY
    // ==========================================

    private static void printMonitoringSummary() {

        System.out.println();

        System.out.println(
                "=============================================="
        );

        System.out.println(
                "             MONITORING COMPLETED"
        );

        System.out.println(
                "=============================================="
        );

        System.out.println(
                "Remote IPs Observed : "
                        + ipPorts.size()
        );

        System.out.println(
                "Connections Observed: "
                        + displayedConnections.size()
        );

        System.out.println(
                "Security Alerts     : "
                        + alertedIPs.size()
        );


        if (
                alertedIPs.isEmpty()
        ) {

            System.out.println(
                    "Status              : "
                            + "No port scan detected"
            );

        } else {

            System.out.println(
                    "Status              : "
                            + "Suspicious activity detected"
            );
        }


        System.out.println(
                "Log File            : "
                        + LOG_FILE
        );

        System.out.println(
                "=============================================="
        );
    }
}