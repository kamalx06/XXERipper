import com.sun.net.httpserver.HttpServer;
import java.io.*;
import java.net.InetSocketAddress;
import java.util.concurrent.Executors;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.xml.sax.InputSource;

public class XxeJavaLab {

    public static void main(String[] args) throws Exception {
        System.setProperty("sun.net.client.defaultConnectTimeout", "5000");
        System.setProperty("sun.net.client.defaultReadTimeout", "5000");

        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 5001), 0);
        server.setExecutor(Executors.newFixedThreadPool(8));

        server.createContext("/xml/error", exchange -> {
            try {
                if (!"POST".equals(exchange.getRequestMethod())) {
                    exchange.sendResponseHeaders(405, -1);
                    return;
                }

                ByteArrayOutputStream buf = new ByteArrayOutputStream();
                exchange.getRequestBody().transferTo(buf);
                byte[] body = buf.toByteArray();

                try {
                    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

                    // Explicitly enable the insecure defaults that older
                    // JDKs shipped with. Without these five lines, JDK
                    // 17+ refuses to resolve external entities or fetch
                    // external DTDs, and no XXE technique works.
                    dbf.setFeature(
                        "http://xml.org/sax/features/external-general-entities",
                        true);
                    dbf.setFeature(
                        "http://xml.org/sax/features/external-parameter-entities",
                        true);
                    dbf.setFeature(
                        "http://apache.org/xml/features/nonvalidating/load-external-dtd",
                        true);
                    dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "all");
                    dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "all");

                    DocumentBuilder db = dbf.newDocumentBuilder();
                    db.parse(new InputSource(new ByteArrayInputStream(body)));

                    byte[] resp = "parsed ok".getBytes();
                    exchange.sendResponseHeaders(200, resp.length);
                    exchange.getResponseBody().write(resp);
                } catch (Exception e) {
                    byte[] resp = ("XML parse error: " + e).getBytes();
                    exchange.sendResponseHeaders(500, resp.length);
                    exchange.getResponseBody().write(resp);
                }
            } finally {
                exchange.close();
            }
        });

        server.start();
        System.out.println("[*] Java XXE lab on http://127.0.0.1:5001");
    }
}
