import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

public class FTPServer {
    private int port;
    private String rootDirectory;
    private String username;
    private String password;
    private boolean anonymousEnabled;
    private int passivePortMin;
    private int passivePortMax;
    private String listeningAddress;
    private ServerSocket dataSocket;

    public FTPServer(String configFilePath) throws IOException {
        loadConfiguration(configFilePath);
    }

    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("Użycie: java FTPServer <ścieżka_do_pliku_konfiguracyjnego>");
            return;
        }

        String configFilePath = args[0];

        try {
            FTPServer server = new FTPServer(configFilePath);
            server.start();
        } catch (IOException e) {
            System.err.println("Błąd: " + e.getMessage());
        }
    }

    private void start() {
        System.out.println("Serwer FTP uruchomiony na adresie " + listeningAddress + " i porcie " + port);
        try (ServerSocket serverSocket = new ServerSocket(port, 50, InetAddress.getByName(listeningAddress))) {
            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("Nowe połączenie od " + clientSocket.getInetAddress());
                new Thread(() -> handleClient(clientSocket)).start();
            }
        } catch (IOException e) {
            System.err.println("Błąd podczas działania serwera: " + e.getMessage());
        }
    }

    private void handleClient(Socket clientSocket) {
        ClientSession session = new ClientSession(clientSocket);

        try (BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
             PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true)) {

            out.println("220 Witaj na serwerze FTP!");

            String command;
            while ((command = in.readLine()) != null) {
                System.out.println("Komenda od klienta: " + command);

                String response = processCommand(command, session);
                out.println(response);

                if (response.startsWith("221")) {
                    break;
                }
            }

        } catch (IOException e) {
            System.err.println("Błąd podczas obsługi klienta: " + e.getMessage());
        }
    }

    private String processCommand(String command, ClientSession session) {
        String[] parts = command.split(" ", 2);
        String cmd = parts[0].toUpperCase();
        String argument = parts.length > 1 ? parts[1].trim() : "";

        switch (cmd) {
            case "USER":
                return handleUser(argument, session);
            case "PASS":
                return handlePass(argument, session);
            case "QUIT":
                return "221 Do widzenia!";
            case "PASV":
                return handlePasv(session);
            default:
                return "502 Komenda nie zaimplementowana.";
        }
    }

    private String handleUser(String username, ClientSession session) {
        if (username.equalsIgnoreCase("anonymous") && anonymousEnabled) {
            session.setUsername("anonymous");
            return "331 Anonimowy dostęp, proszę podać e-mail jako hasło.";
        } else if (username.equals(this.username)) {
            session.setUsername(username);
            return "331 Proszę podać hasło.";
        } else {
            return "530 Nieznany użytkownik.";
        }
    }

    private String handlePass(String password, ClientSession session) {
        if ("anonymous".equals(session.getUsername()) && anonymousEnabled) {
            session.setAuthenticated(true);
            return "230 Zalogowano jako użytkownik anonimowy.";
        } else if (this.password.equals(password) && this.username.equals(session.getUsername())) {
            session.setAuthenticated(true);
            return "230 Zalogowano pomyślnie.";
        } else {
            return "530 Nieprawidłowe dane logowania.";
        }
    }

    private String handlePasv(ClientSession session) {
        try {
            int port = ThreadLocalRandom.current().nextInt(passivePortMin, passivePortMax + 1);
            InetAddress clientAddress = session.getControlSocket().getInetAddress();

            // Tworzenie gniazda serwera dla danych na wylosowanym porcie
            dataSocket = new ServerSocket(port, 1, clientAddress);
            dataSocket.setSoTimeout(30000);

            String ipAddress = clientAddress.getHostAddress().replace(".", ",");
            int p1 = port / 256;
            int p2 = port % 256;

            session.setPassiveMode(true);
            session.setDataSocket(dataSocket);

            return String.format("227 Entering Passive Mode (%s,%d,%d).", ipAddress, p1, p2);
        } catch (IOException e) {
            return "425 Nie można otworzyć trybu pasywnego.";
        }
    }

    private void loadConfiguration(String configFilePath) throws IOException {
        Properties config = new Properties();
        try (FileInputStream fis = new FileInputStream(configFilePath)) {
            config.load(fis);
        }

        this.port = Integer.parseInt(config.getProperty("port", "21"));
        this.rootDirectory = config.getProperty("rootDirectory", ".");
        this.username = config.getProperty("username", "admin");
        this.password = config.getProperty("password", "admin");
        this.anonymousEnabled = Boolean.parseBoolean(config.getProperty("anonymousEnabled", "false"));
        this.passivePortMin = Integer.parseInt(config.getProperty("passivePortMin", "50000"));
        this.passivePortMax = Integer.parseInt(config.getProperty("passivePortMax", "51000"));
        this.listeningAddress = config.getProperty("listeningAddress", "0.0.0.0");
    }
}

class ClientSession {
    private String username;
    private boolean authenticated;
    private boolean passiveMode;
    private ServerSocket dataSocket;
    private Socket controlSocket;

    public ClientSession(Socket controlSocket) {
        this.username = null;
        this.authenticated = false;
        this.passiveMode = false;
        this.dataSocket = null;
        this.controlSocket = controlSocket;
    }

    public Socket getControlSocket() {
        return controlSocket;
    }

    public boolean isPassiveMode() {
        return passiveMode;
    }

    public void setPassiveMode(boolean passiveMode) {
        this.passiveMode = passiveMode;
    }

    public ServerSocket getDataSocket() {
        return dataSocket;
    }

    public void setDataSocket(ServerSocket dataSocket) {
        this.dataSocket = dataSocket;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public boolean isAuthenticated() {
        return authenticated;
    }

    public void setAuthenticated(boolean authenticated) {
        this.authenticated = authenticated;
    }
}
