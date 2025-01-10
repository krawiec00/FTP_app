import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

public class FTPServer {
    private int port;
    private String rootDirectory;
    private boolean anonymousEnabled;
    private int passivePortMin;
    private int passivePortMax;
    private String listeningAddress;
    private ServerSocket dataSocket;
    private Map<String, String> users = new HashMap<>();


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
        session.updateLastActivityTime(); // Ustawienie początkowego czasu aktywności

        // Limit czasu w sekundach
        final int TIMEOUT_SECONDS = 300;

        Thread timeoutThread = new Thread(() -> {
            try {
                while (true) {
                    Thread.sleep(5000);
                    if (System.currentTimeMillis() - session.getLastActivityTime() > TIMEOUT_SECONDS * 1000) {
                        System.out.println("Client disconnected due to inactivity: " + session.getUsername());
                        clientSocket.close();
                        break;
                    }
                }
            } catch (InterruptedException | IOException e) {
                System.err.println("Error in timeout thread: " + e.getMessage());
            }
        });
        timeoutThread.start();

        try (BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
             PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true)) {

            out.println("220 Welcome to the FTP server!");

            String command;
            while ((command = in.readLine()) != null) {
                System.out.println("Komenda od klienta: " + command);

                // Aktualizacja czasu aktywności po każdej komendzie
                session.updateLastActivityTime();

                String response = processCommand(command, session);
                out.println(response);

                if (response.startsWith("221")) {
                    break;
                }
            }

        } catch (IOException e) {
            System.err.println("Błąd podczas obsługi klienta: " + e.getMessage());
        } finally {
            try {
                clientSocket.close();
            } catch (IOException e) {
                System.err.println("Błąd podczas zamykania połączenia: " + e.getMessage());
            }
        }
    }


    private String processCommand(String command, ClientSession session) throws IOException {
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
                return ensureAuthenticated(session) ? handlePasv(session) : "530 Najpierw się zaloguj.";
            case "PWD":
                return ensureAuthenticated(session) ? handlePwd(session) : "530 Najpierw się zaloguj.";
            case "CDUP":
                return ensureAuthenticated(session) ? handleCdup(session) : "530 Please log in first.";
            case "CWD":
                return ensureAuthenticated(session) ? handleCwd(argument, session) : "530 Please log in first.";
            case "LIST":
                return ensureAuthenticated(session) ? handleList(session) : "530 Please log in first.";
            case "TYPE":
                return ensureAuthenticated(session) ? handleType(argument, session) : "530 Please log in first.";
            case "MKD":
                return ensureAuthenticated(session) ? handleMkd(argument, session) : "530 Please log in first.";
            case "RMD":
                return ensureAuthenticated(session) ? handleRmd(argument, session) : "530 Please log in first.";
            case "STOR":
                return ensureAuthenticated(session) ? handleStor(argument, session) : "530 Please log in first.";
            case "RETR":
                return ensureAuthenticated(session) ? handleRetr(argument, session) : "530 Please log in first.";
            case "DELE":
                return ensureAuthenticated(session) ? handleDele(argument, session) : "530 Please log in first.";
            case "MODE":
                return ensureAuthenticated(session) ? handleMode(argument) : "530 Please log in first.";
            case "STRU":
                return ensureAuthenticated(session) ? handleStru(argument) : "530 Please log in first.";
            default:
                return "502 Command not implemented.";
        }
    }

    private boolean ensureAuthenticated(ClientSession session) {
        if (!session.isAuthenticated()) {
            System.err.println("Unauthorized use of commend by user: " + session.getUsername());
            return false;
        }
        return true;
    }


    private String handleUser(String username, ClientSession session) {
        if (username.equalsIgnoreCase("anonymous") && anonymousEnabled) {
            session.setUsername("anonymous");
            return "331 Anonymous access granted, please send your email as the password.";
        } else if (users.containsKey(username)) {
            session.setUsername(username);
            return "331 Password required.";
        } else {
            return "530 Unknown user.";
        }
    }


    private String handlePass(String password, ClientSession session) {

        session.setUserRootDirectory(new File(rootDirectory));
        String userRootDirectory = String.valueOf(session.getUserRootDirectory());
        if ("anonymous".equals(session.getUsername()) && anonymousEnabled) {
            session.setAuthenticated(true);
            session.setUserRootDirectory(new File(userRootDirectory)); // Anonymous ma katalog główny serwera
            session.setCurrentDirectory(session.getUserRootDirectory()); // Ustaw katalog początkowy
            return "230 Logged in as anonymous.";
        } else if (users.containsKey(session.getUsername()) && users.get(session.getUsername()).equals(password)) {
            session.setAuthenticated(true);

            // Utwórz katalog użytkownika w `rootDirectory`
            File userDirectory = new File(userRootDirectory, session.getUsername());
            if (!userDirectory.exists() && !userDirectory.mkdir()) {
                System.err.println("Nie udało się utworzyć katalogu dla użytkownika: " + session.getUsername());
                return "530 Internal server error while creating user directory.";
            }

            session.setUserRootDirectory(userDirectory); // Przypisz katalog użytkownika
            session.setCurrentDirectory(userDirectory); // Ustaw jako katalog bieżący
            return "230 User logged in successfully.";
        } else {
            return "530 Invalid login credentials.";
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
            System.out.println("PORT DATASOCKET: " + session.getDataSocket());
            return String.format("227 Entering Passive Mode (%s,%d,%d).", ipAddress, p1, p2);
        } catch (IOException e) {
            return "425 Can't open data connection.";
        }
    }

    private String handlePwd(ClientSession session) {
        String userRootDirectory = String.valueOf(session.getUserRootDirectory());
        File currentDirectory = session.getCurrentDirectory();
        String relativePath = currentDirectory.getAbsolutePath().substring(userRootDirectory.length());
        relativePath = normalizePath(relativePath);
        return "257 \"" + (relativePath.isEmpty() ? "\\" : relativePath) + "\" is current directory";
    }


    private String handleCdup(ClientSession session) {
        File currentDirectory = session.getCurrentDirectory();
        File parentDirectory = currentDirectory.getParentFile();

        if (parentDirectory == null || !parentDirectory.getAbsolutePath().startsWith(session.getUserRootDirectory().getAbsolutePath())) {
            return "550 Requested action not taken.";
        }

        session.setCurrentDirectory(parentDirectory);
        return "200 Directory successfully changed.";
    }



    private String handleCwd(String argument, ClientSession session) throws IOException {
        if (argument.isEmpty()) {
            return "501 Syntax error in parameters or arguments.";
        }
        String userRootDirectory = String.valueOf(session.getUserRootDirectory());
        File targetDirectory;

        if (argument.startsWith("\\")) {
            targetDirectory = new File(userRootDirectory, argument).getCanonicalFile();
        } else {
            targetDirectory = new File(session.getCurrentDirectory(), argument).getCanonicalFile();
        }

        if (!targetDirectory.exists() || !targetDirectory.isDirectory()) {
            return "550 Requested action not taken.";
        }

        if (!targetDirectory.getAbsolutePath().startsWith(userRootDirectory)) {
            return "550 Requested action not taken.";
        }

        session.setCurrentDirectory(targetDirectory);
        String relativePath = normalizePath(targetDirectory.getAbsolutePath().substring(userRootDirectory.length()));
        return "250 Catalog changed to " + (relativePath.isEmpty() ? "/" : relativePath);
    }


    private String handleList(ClientSession session) {
        if (!session.isPassiveMode() || session.getDataSocket() == null) {
            return "425 Can't open data connection";
        }
        try (Socket dataSocket = session.getDataSocket().accept();
             PrintWriter dataOut = new PrintWriter(dataSocket.getOutputStream(), true)) {

            // Wysyłamy informację do klienta o rozpoczęciu transferu danych
            PrintWriter controlOut = new PrintWriter(session.getControlSocket().getOutputStream(), true);
            controlOut.println("150 File status okay; about to open data connection.");

            // Pobieramy listę plików i katalogów w bieżącym katalogu roboczym
            File currentDir = session.getCurrentDirectory();
            File[] files = currentDir.listFiles();
            if (files != null) {
                for (File file : files) {
                    String fileInfo = formatFileInfo(file, session);
                    dataOut.println(fileInfo);
                }
            }
            // Zamykanie połączenia danych i informowanie o zakończeniu
            session.getDataSocket().close();
            session.setDataSocket(null); // Wyłączenie trybu PASV po zakończeniu transferu
            return "226 Closing data connection.\n" +
                    "             Requested file action successful (for example, file\n" +
                    "             transfer or file abort).";
        } catch (IOException e) {
            return "425 Can't open data connection.";
        }
    }

    private String formatFileInfo(File file, ClientSession session) {
        // Określenie uprawnień
        String permissions = (file.isDirectory() ? "d" : "-")
                + (file.canRead() ? "r" : "-")
                + (file.canWrite() ? "w" : "-")
                + (file.canExecute() ? "x" : "-")
                + "r--r--";

        // Liczba linków (przyjmijmy domyślnie 1)
        int links = 1;

        // Właściciel i grupa (domyślne wartości)
        String owner = session.getUsername();
        String group = " ";

        // Rozmiar pliku
        long size = file.length();

        Date lastModified = new Date(file.lastModified());
        String formattedDate = new java.text.SimpleDateFormat("MMM dd HH:mm").format(lastModified);

        String name = normalizePath(file.getName());

        return String.format("%s %2d %s %s %10d %s %s",
                permissions, links, owner, group, size, formattedDate, name);
    }


    private String handleType(String argument, ClientSession session) {
        if (argument.isEmpty()) {
            return "501 Syntax error in parameters or arguments.";
        }
        switch (argument.toUpperCase()) {
            case "A": // ASCII
                session.setTransferType(ClientSession.TransferType.ASCII);
                return "200 Transfer type changed to ASCII.";
            case "I": // Binary (Image)
                session.setTransferType(ClientSession.TransferType.BINARY);
                return "200 Transfer type changed to Binary.";
            default:
                return "504 Command not implemented for that parameter.";
        }
    }

    private String handleMkd(String argument, ClientSession session) {
        if (argument == null || argument.isEmpty()) {
            return "501 Syntax error in parameters or arguments.";
        }

        File newDir = new File(session.getCurrentDirectory(), argument);

        if (newDir.exists()) {
            return "550 Directory already exists.";
        }

        if (newDir.mkdir()) {
            return "257 \"" + newDir.getName() + "\" created.";
        } else {
            return "550 Failed to create directory.";
        }
    }

    // Obsługa polecenia RMD (Remove Directory)
    private String handleRmd(String argument, ClientSession session) {
        if (argument == null || argument.isEmpty()) {
            return "501 Syntax error in parameters or arguments.";
        }

        File targetDir = new File(session.getCurrentDirectory(), argument);

        if (!targetDir.exists()) {
            return "550 Directory does not exist.";
        }

        if (!targetDir.isDirectory()) {
            return "550 Specified path is not a directory.";
        }

        if (targetDir.delete()) {
            return "250 Directory deleted.";
        } else {
            return "550 Failed to delete directory. Make sure it is empty.";
        }
    }

    private String handleStor(String argument, ClientSession session) {
        if (argument == null || argument.isEmpty()) {
            return "501 Missing file name.";
        }

        if (!session.isPassiveMode() || session.getDataSocket() == null) {
            return "425 Passive mode not enabled.";
        }

        File targetFile = new File(session.getCurrentDirectory(), argument);

        try (Socket dataSocket = session.getDataSocket().accept();
             FileOutputStream fileOut = new FileOutputStream(targetFile);
             InputStream dataIn = dataSocket.getInputStream()) {

            PrintWriter controlOut = new PrintWriter(session.getControlSocket().getOutputStream(), true);
            controlOut.println("150 Opening data connection for file transfer.");

            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = dataIn.read(buffer)) != -1) {
                fileOut.write(buffer, 0, bytesRead);
            }

            controlOut.println("226 Transfer complete.");
            session.setDataSocket(null); // Wyłączenie trybu PASV po zakończeniu transferu
            return "";
        } catch (IOException e) {
            return "425 Error during file transfer.";
        }
    }

    private String handleRetr(String argument, ClientSession session) {
        if (argument == null || argument.isEmpty()) {
            return "501 Missing file name.";
        }

        if (!session.isPassiveMode() || session.getDataSocket() == null) {
            return "425 Passive mode not enabled.";
        }

        File targetFile = new File(session.getCurrentDirectory(), argument);

        if (!targetFile.exists() || !targetFile.isFile()) {
            return "550 File does not exist.";
        }

        try (Socket dataSocket = session.getDataSocket().accept();
             FileInputStream fileIn = new FileInputStream(targetFile);
             OutputStream dataOut = dataSocket.getOutputStream()) {

            PrintWriter controlOut = new PrintWriter(session.getControlSocket().getOutputStream(), true);
            controlOut.println("150 Opening data connection for file transfer.");

            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = fileIn.read(buffer)) != -1) {
                dataOut.write(buffer, 0, bytesRead);
            }
            dataOut.flush();

            controlOut.println("226 Transfer complete.");
            session.setDataSocket(null); // Wyłączenie trybu PASV po zakończeniu transferu
            return "";
        } catch (IOException e) {
            return "425 Error during file transfer.";
        }
    }

    private String handleDele(String argument, ClientSession session) {
        if (argument == null || argument.isEmpty()) {
            return "501 Missing file name.";
        }

        File targetFile = new File(session.getCurrentDirectory(), argument);

        if (!targetFile.exists()) {
            return "550 File does not exist.";
        }

        if (!targetFile.isFile()) {
            return "550 Specified path is not a file.";
        }

        if (targetFile.delete()) {
            return "250 File deleted successfully.";
        } else {
            return "450 Unable to delete the file.";
        }
    }

    private String handleMode(String argument) {
        if (argument.isEmpty()) {
            return "501 Brak argumentu.";
        }
        if ("S".equalsIgnoreCase(argument)) {
            return "200 Tryb transferu ustawiony na Stream.";
        } else {
            return "504 Nieobsługiwany tryb transferu.";
        }
    }

    private String handleStru(String argument) {
        if (argument.isEmpty()) {
            return "501 Syntax error in parameters or arguments.";
        }
        if ("F".equalsIgnoreCase(argument)) {
            return "200 Command okay.";
        } else {
            return "504 Command not implemented for that parameter.";
        }
    }


    private String normalizePath(String path) {
        return path.replace("/", "\\");
    }


    private void loadConfiguration(String configFilePath) throws IOException {
        Properties config = new Properties();
        try (FileInputStream fis = new FileInputStream(configFilePath)) {
            config.load(fis);
        }

        this.port = Integer.parseInt(config.getProperty("port", "21"));
        this.rootDirectory = config.getProperty("rootDirectory", ".");
        this.anonymousEnabled = Boolean.parseBoolean(config.getProperty("anonymousEnabled", "false"));
        this.passivePortMin = Integer.parseInt(config.getProperty("passivePortMin", "50000"));
        this.passivePortMax = Integer.parseInt(config.getProperty("passivePortMax", "51000"));
        this.listeningAddress = config.getProperty("listeningAddress", "0.0.0.0");

        for (String key : config.stringPropertyNames()) {
            if (key.startsWith("users.")) {
                String username = key.substring(6);
                String password = config.getProperty(key);
                users.put(username, password);
            }
        }
    }

}

class ClientSession {
    private String username;
    private boolean authenticated;
    private boolean passiveMode;
    private ServerSocket dataSocket;
    private Socket controlSocket;
    private File currentDirectory;
    private File userRootDirectory;
    private TransferType transferType = TransferType.ASCII;
    private long lastActivityTime;

    public ClientSession(Socket controlSocket) {
        this.username = null;
        this.authenticated = false;
        this.passiveMode = false;
        this.dataSocket = null;
        this.controlSocket = controlSocket;
        this.currentDirectory = null;
    }

    public void updateLastActivityTime() {
        this.lastActivityTime = System.currentTimeMillis();
    }

    public long getLastActivityTime() {
        return lastActivityTime;
    }

    public File getUserRootDirectory() {
        return userRootDirectory;
    }

    public void setUserRootDirectory(File userRootDirectory) {
        this.userRootDirectory = userRootDirectory;
    }

    public enum TransferType {
        ASCII, BINARY
    }

    public TransferType getTransferType() {
        return transferType;
    }

    public void setTransferType(TransferType transferType) {
        this.transferType = transferType;
    }

    public File getCurrentDirectory() {
        return currentDirectory;
    }

    public void setCurrentDirectory(File currentDirectory) {
        this.currentDirectory = currentDirectory;
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
