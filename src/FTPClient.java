import java.io.*;
import java.net.*;
import java.util.regex.*;

public class FTPClient {

    private static String host;
    private static int port;
    private static String user;
    private static String pass;
    private static String path;
    private static String path2;
    private static Socket controlSocket;
    private static BufferedReader reader;
    private static BufferedWriter writer;
    private static Socket dataSocket; // Socket dla kanału danych

    public static void parseUrl(String url) {
        try {
            Pattern urlPattern = Pattern.compile("ftp://(\\w+)(?::(\\w+))?@([\\d\\.]+):(\\d+)?/(.*)");
            Matcher matcher = urlPattern.matcher(url);

            if (matcher.find()) {
                user = matcher.group(1);
                pass = matcher.group(2) != null ? matcher.group(2) : "";
                host = matcher.group(3);
                port = matcher.group(4) != null ? Integer.parseInt(matcher.group(4)) : 21;
                path = matcher.group(5);
            } else {
                System.out.println("Invalid FTP URL format ");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void parseSecondUrl(String url) {
        try {
            Pattern urlPattern = Pattern.compile("ftp://(\\w+)(?::(\\w+))?@([\\d\\.]+):(\\d+)?/(.*)");
            Matcher matcher = urlPattern.matcher(url);

            if (matcher.find()) {
                path2 = matcher.group(5);
            } else {
                System.out.println("Invalid FTP URL format ");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static boolean isLocalPath(String path) {
        // Lokalna ścieżka: zaczyna się od litery dysku lub "/" (Unix) lub zawiera separator systemowy
        return path.matches("^[a-zA-Z]:\\\\.*") || path.startsWith("/") || path.contains(File.separator);
    }

    public static void connect() {
        try {
            controlSocket = new Socket(host, port);
            reader = new BufferedReader(new InputStreamReader(controlSocket.getInputStream()));
            writer = new BufferedWriter(new OutputStreamWriter(controlSocket.getOutputStream()));

            // Read server's initial response
            System.out.println(reader.readLine());

            sendCommand("USER " + user);
            System.out.println(reader.readLine());

            sendCommand("PASS " + pass);
            System.out.println(reader.readLine());

            sendCommand("TYPE I");
            String response = reader.readLine();
            System.out.println(response);
            if (response.startsWith("530")) {
                disconnect();
                System.exit(0);
            }

            sendCommand("MODE S");
            System.out.println(reader.readLine());

            sendCommand("STRU F");
            System.out.println(reader.readLine());
        } catch (UnknownHostException e) {
            System.out.println("Error: Unable to resolve host '" + host + "'. Please check the address.");
            System.exit(1);
        } catch (IOException e) {
            System.out.println("Error: Unable to connect to " + host + " on port " + port + ". Please check the address or port.");
            System.exit(1);
        }
    }


    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: usftp [operation] [param1] [param2]");
            return;
        }
        String command = args[0];
        String param1 = args[1];
        String param2 = args.length > 2 ? args[2] : null;

        try {
            if (isLocalPath(param1) && param2 != null) {  //param1 jest ścięzką komputera a 2 na serwer
                parseUrl(param2);
                param2 = path;
            } else if (param2 != null && isLocalPath(param2)) {  //param2 to lokalna a 1 serwera
                parseUrl(param1);
                param1 = path;
            } else if (!isLocalPath(param1) && param2 != null && !isLocalPath(param2)) {  //obie są serwera
                parseUrl(param1);
                param1 = path;
                parseSecondUrl(param2);
                param2 = path2;
            } else if (param2 == null) {    //jest tylko jedna od serwera
                parseUrl(param1);
                param1 = path;
            }
            connect();

            switch (command.toLowerCase()) {
                case "ls":
                    list(param1);
                    break;
                case "mkdir":
                    makeDirectory(param1);
                    break;
                case "rm":
                    deleteFile(param1);
                    break;
                case "rmdir":
                    removeDirectory(param1);
                    break;
                case "cp":
                    if (isLocalPath(param1))
                        storeFile(param1, path);
                    else if (param2 != null && isLocalPath(param2))
                        retrieveFile(path, param2);
                    else if (!isLocalPath(param1) && !isLocalPath(param2))
                        copyFileOnServer(path, path2);
                    break;
                case "mv":
                    if (isLocalPath(param1)) {
                        storeFile(param1, path);
                        deleteLocalFile(param1);
                    } else if (param2 != null && isLocalPath(param2)) {
                        retrieveFile(path, param2);
                        deleteFile(path);
                    } else if (!isLocalPath(param1) && !isLocalPath(param2)) {
                        copyFileOnServer(path, path2);
                        deleteFile(path);
                    }
                    break;
                default:
                    System.out.println("Unknown command: " + command);
            }
            disconnect();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void disconnect() throws IOException {
        System.out.println(reader.readLine());
        sendCommand("QUIT");
        System.out.println(reader.readLine());
        controlSocket.close();
    }

    public static void makeDirectory(String directory) throws IOException {
        sendCommand("MKD " + directory);
        System.out.println(reader.readLine());
    }

    public static void removeDirectory(String directory) throws IOException {
        sendCommand("RMD " + directory);
        System.out.println(reader.readLine());
    }

    private static void storeFile(String localPath, String remoteDirectory) throws IOException {
        File file = new File(localPath);
        if (!file.exists() || !file.isFile()) {
            disconnect();
            throw new IOException("File does not exist or is not a valid file: " + localPath);
        }

        // Wyodrębnij nazwę pliku
        String fileName = file.getName();
        String remotePath = remoteDirectory.endsWith("/") ? remoteDirectory + fileName : remoteDirectory + "/" + fileName;

        try (FileInputStream fileInputStream = new FileInputStream(file)) {
            openPassiveMode();
            sendCommand("STOR " + remotePath);
            String response = reader.readLine();


            if (response.startsWith("501") || response.startsWith("550")) {
                errorExit(response);
            }
            System.out.println(response);
            try (OutputStream dataOut = dataSocket.getOutputStream()) {
                byte[] buffer = new byte[4096];
                int bytesRead;

                while ((bytesRead = fileInputStream.read(buffer)) != -1) {
                    dataOut.write(buffer, 0, bytesRead);
                }
                dataOut.flush();
            }
        } finally {
            if (dataSocket != null && !dataSocket.isClosed()) {
                dataSocket.close();
            }
        }
    }


    private static void retrieveFile(String remotePath, String localPath) throws IOException {
        openPassiveMode();
        sendCommand("RETR " + remotePath);
        String response = reader.readLine();
        System.out.println(response);

        if (!response.startsWith("150")) {
            errorExit(response);
        }

        // Wyodrębnij nazwę pliku z remotePath
        String fileName = java.nio.file.Paths.get(remotePath).getFileName().toString();
        File outputFile = new File(localPath, fileName);

        try (FileOutputStream fileOutputStream = new FileOutputStream(outputFile);
             InputStream dataIn = dataSocket.getInputStream()) {

            byte[] buffer = new byte[4096];
            int bytesRead;

            while ((bytesRead = dataIn.read(buffer)) != -1) {
                fileOutputStream.write(buffer, 0, bytesRead);
            }
            fileOutputStream.flush();
        } catch (IOException e) {
            throw new IOException("Error retriving file: " + e.getMessage(), e);
        } finally {
            dataSocket.close();
        }
    }


    private static void copyFileOnServer(String sourcePath, String destinationDirectory) throws IOException {
        // Wyodrębnij nazwę pliku ze ścieżki źródłowej
        String fileName = java.nio.file.Paths.get(sourcePath).getFileName().toString();
        String destinationPath = destinationDirectory.endsWith("/") ? destinationDirectory + fileName : destinationDirectory + "/" + fileName;

        // Kanał danych dla odczytu
        openPassiveMode();
        sendCommand("RETR " + sourcePath);
        String response = reader.readLine();
        if (!response.startsWith("150")) {
            errorExit(response);
        }
        System.out.println(response);
        Socket dataSocketRead = dataSocket;

        // Kanał danych dla zapisu
        openPassiveMode();
        sendCommand("STOR " + destinationPath);
        response = reader.readLine();
        if (!response.startsWith("150") || response.startsWith("550")) {
            errorExit(response);
        }
        Socket dataSocketWrite = dataSocket;

        try (
                InputStream dataIn = dataSocketRead.getInputStream();
                OutputStream dataOut = dataSocketWrite.getOutputStream()
        ) {
            byte[] buffer = new byte[4096];
            int bytesRead;

            while ((bytesRead = dataIn.read(buffer)) != -1) {
                dataOut.write(buffer, 0, bytesRead);
            }
            dataOut.flush();
        } finally {
            if (dataSocketRead != null && !dataSocketRead.isClosed()) {
                dataSocketRead.close();
            }
            if (dataSocketWrite != null && !dataSocketWrite.isClosed()) {
                dataSocketWrite.close();
            }
        }
    }


    public static void deleteFile(String filePath) throws IOException {
        sendCommand("DELE " + filePath);
        System.out.println(reader.readLine());
    }

    public static void deleteLocalFile(String filePath) throws IOException {
        try {
            File file = new File(filePath);
            file.delete();
        } catch (Exception e) {
            throw new IOException("ERROR removing file after mv:" + e.getMessage(), e);
        }
    }

    public static void list(String path) throws IOException {
        openPassiveMode();
        sendCommand("LIST " + path);
        String response = reader.readLine();
        if (response.startsWith("550")) {
            System.out.println(response);
            sendCommand("QUIT");
            System.out.println(reader.readLine());
            System.exit(0);
        }
        try (BufferedReader dataReader = new BufferedReader(new InputStreamReader(dataSocket.getInputStream()))) {
            while ((response = dataReader.readLine()) != null) {
                System.out.println(response);
            }
        } finally {
            if (dataSocket != null && !dataSocket.isClosed()) {
                dataSocket.close();
            }
        }
    }

    private static void openPassiveMode() throws IOException {
        sendCommand("PASV");
        String response = reader.readLine();   //opoźnienie czytania odpowiedzi, potrzebujemy dwóch odczytów
        String response2 = reader.readLine();
        System.out.println(response2); // Debugowanie odpowiedzi PASV

        // Wyodrębnienie adresu IP i portu z odpowiedzi
        Pattern pasvPattern = Pattern.compile("\\((\\d+),(\\d+),(\\d+),(\\d+),(\\d+),(\\d+)\\)");
        Matcher matcher = pasvPattern.matcher(response2);

        if (matcher.find()) {
            int ip1 = Integer.parseInt(matcher.group(1));
            int ip2 = Integer.parseInt(matcher.group(2));
            int ip3 = Integer.parseInt(matcher.group(3));
            int ip4 = Integer.parseInt(matcher.group(4));
            int port1 = Integer.parseInt(matcher.group(5));
            int port2 = Integer.parseInt(matcher.group(6));

            String dataHost = ip1 + "." + ip2 + "." + ip3 + "." + ip4;
            int dataPort = (port1 * 256) + port2;

            System.out.println("Connecting to data channel at " + dataHost + ":" + dataPort); // Debugowanie adresu i portu
            dataSocket = new Socket(dataHost, dataPort); // Ustanowienie połączenia dla kanału danych
        } else {
            throw new IOException("Could not parse PASV response.");
        }
    }

    private static void sendCommand(String command) throws IOException {
        writer.write(command + "\r\n");
        writer.flush();
    }

    private static void errorExit(String response) throws IOException {
        System.out.println(response);
        sendCommand("QUIT");
        System.out.println(reader.readLine());
        System.exit(0);
    }
}
