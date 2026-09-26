// Java HTTP/1.1 test service for the e2e suite (HTTP/2 skipped — the JDK
// has no built-in HTTP/2 *server*, only an HTTP/2 client; a real server
// needs Jetty/Netty, not worth it for this harness).
// Usage: java Server <port>
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

public class Server {
    public static void main(String[] args) throws IOException {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8081;
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);

        server.createContext("/users", (HttpExchange ex) -> {
            byte[] body = "[{\"id\":1,\"name\":\"alice\"},{\"id\":2,\"name\":\"bob\"}]".getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().add("Content-Type", "application/json");
            ex.sendResponseHeaders(200, body.length);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(body);
            }
        });

        server.createContext("/echo", (HttpExchange ex) -> {
            byte[] body = ex.getRequestBody().readAllBytes();
            ex.sendResponseHeaders(200, body.length);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(body);
            }
        });

        server.createContext("/error", (HttpExchange ex) -> {
            byte[] body = "boom".getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(500, body.length);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(body);
            }
        });

        server.setExecutor(null);
        server.start();
        System.out.println("java-service: http/1.1 on :" + port);
    }
}
