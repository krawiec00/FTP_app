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
                return ensureAuthenticated(session) ? handleCdup(session) : "530 Najpierw się zaloguj.";
            case "CWD":
                return ensureAuthenticated(session) ? handleCwd(argument, session) : "530 Najpierw się zaloguj.";
            case "LIST":
                return ensureAuthenticated(session) ? handleList(session) : "530 Najpierw się zaloguj.";
            case "TYPE":
                return ensureAuthenticated(session) ? handleType(argument, session) : "530 Najpierw się zaloguj.";
            case "MKD":
                return ensureAuthenticated(session) ? handleMkd(argument, session) : "530 Najpierw się zaloguj.";
            case "RMD":
                return ensureAuthenticated(session) ? handleRmd(argument, session) : "530 Najpierw się zaloguj.";
            case "STOR":
                return ensureAuthenticated(session) ? handleStor(argument, session) : "530 Please log in first.";
            case "RETR":
                return ensureAuthenticated(session) ? handleRetr(argument, session) : "530 Please log in first.";
            case "DELE":
                return ensureAuthenticated(session) ? handleDele(argument, session) : "530 Please log in first.";

            default:
                return "502 Komenda nie zaimplementowana.";
        }
    }

    private boolean ensureAuthenticated(ClientSession session) {
        if (!session.isAuthenticated()) {
            System.err.println("Nieautoryzowana próba użycia komendy przez użytkownika: " + session.getUsername());
            return false;
        }
        return true;
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
            session.setCurrentDirectory(new File(rootDirectory)); // Ustawienie katalogu startowego
            return "230 Zalogowano jako użytkownik anonimowy.";
        } else if (this.password.equals(password) && this.username.equals(session.getUsername())) {
            session.setAuthenticated(true);
            session.setCurrentDirectory(new File(rootDirectory)); // Ustawienie katalogu startowego
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

    private String handlePwd(ClientSession session) {
        File currentDirectory = session.getCurrentDirectory();
        String relativePath = currentDirectory.getAbsolutePath().substring(rootDirectory.length());
        relativePath = normalizePath(relativePath);
        return "257 \"" + (relativePath.isEmpty() ? "\\" : relativePath) + "\" is current directory";
    }


    private String handleCdup(ClientSession session) {
        File currentDirectory = session.getCurrentDirectory();
        File parentDirectory = currentDirectory.getParentFile();

        if (parentDirectory == null || !parentDirectory.getAbsolutePath().startsWith(rootDirectory)) {
            return "550 Nie można przejść wyżej.";
        }

        session.setCurrentDirectory(parentDirectory);
        String relativePath = normalizePath(parentDirectory.getAbsolutePath().substring(rootDirectory.length()));
        return "200 Katalog zmieniony na " + (relativePath.isEmpty() ? "/" : relativePath);
    }


    private String handleCwd(String argument, ClientSession session) throws IOException {
        if (argument.isEmpty()) {
            return "501 Brak argumentu.";
        }

        File targetDirectory = new File(session.getCurrentDirectory(), argument).getCanonicalFile();

        if (!targetDirectory.exists() || !targetDirectory.isDirectory()) {
            return "550 Katalog nie istnieje.";
        }

        if (!targetDirectory.getAbsolutePath().startsWith(rootDirectory)) {
            return "550 Dostęp do katalogu zabroniony.";
        }

        session.setCurrentDirectory(targetDirectory);
        String relativePath = normalizePath(targetDirectory.getAbsolutePath().substring(rootDirectory.length()));
        return "250 Katalog zmieniony na " + relativePath;
    }


    private String handleList(ClientSession session) {
        if (!session.isPassiveMode() || session.getDataSocket() == null) {
            return "425 Tryb pasywny nie został włączony.";
        }
        System.out.println("PORT DATASOCKET: " + session.getDataSocket());
        try (Socket dataSocket = session.getDataSocket().accept();
             PrintWriter dataOut = new PrintWriter(dataSocket.getOutputStream(), true)) {

            // Wysyłamy informację do klienta o rozpoczęciu transferu danych
            PrintWriter controlOut = new PrintWriter(session.getControlSocket().getOutputStream(), true);
            controlOut.println("150 Opening data connection for file list.");

            // Pobieramy listę plików i katalogów w bieżącym katalogu roboczym
            File currentDir = session.getCurrentDirectory();
            File[] files = currentDir.listFiles();
            if (files != null) {
                for (File file : files) {
                    String fileInfo = formatFileInfo(file);
                    dataOut.println(fileInfo);
                }
            }
            // Zamykanie połączenia danych i informowanie o zakończeniu
            session.getDataSocket().close();
            session.setDataSocket(null); // Wyłączenie trybu PASV po zakończeniu transferu
            return "226 Transfer complete.";
        } catch (IOException e) {
            return "425 Błąd podczas transferu danych.";
        }
    }

    private String formatFileInfo(File file) {
        // Określenie uprawnień
        String permissions = (file.isDirectory() ? "d" : "-")
                + (file.canRead() ? "r" : "-")
                + (file.canWrite() ? "w" : "-")
                + (file.canExecute() ? "x" : "-")
                + "r--r--";

        // Liczba linków (przyjmijmy domyślnie 1)
        int links = 1;

        // Właściciel i grupa (domyślne wartości)
        String owner = "user";
        String group = "group";

        // Rozmiar pliku
        long size = file.length();

        // Data modyfikacji
        Date lastModified = new Date(file.lastModified());
        String formattedDate = new java.text.SimpleDateFormat("MMM dd HH:mm").format(lastModified);

        // Nazwa pliku
        String name = normalizePath(file.getName());

        // Tworzymy sformatowany wynik
        return String.format("%s %2d %s %s %10d %s %s",
                permissions, links, owner, group, size, formattedDate, name);
    }


    private String handleType(String argument, ClientSession session) {
        if (argument.isEmpty()) {
            return "501 Brak argumentu.";
        }
        switch (argument.toUpperCase()) {
            case "A": // ASCII
                session.setTransferType(ClientSession.TransferType.ASCII);
                return "200 Tryb transferu ustawiony na ASCII.";
            case "I": // Binary (Image)
                session.setTransferType(ClientSession.TransferType.BINARY);
                return "200 Tryb transferu ustawiony na Binary.";
            default:
                return "504 Nieobsługiwany typ danych.";
        }
    }

    private String handleMkd(String argument, ClientSession session) {
        if (argument == null || argument.isEmpty()) {
            return "501 Missing directory name.";
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
            return "501 Missing directory name.";
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
    private File currentDirectory;
    private TransferType transferType = TransferType.ASCII;

    public ClientSession(Socket controlSocket) {
        this.username = null;
        this.authenticated = false;
        this.passiveMode = false;
        this.dataSocket = null;
        this.controlSocket = controlSocket;
        this.currentDirectory = null; // Ustawiane później po zalogowaniu
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
