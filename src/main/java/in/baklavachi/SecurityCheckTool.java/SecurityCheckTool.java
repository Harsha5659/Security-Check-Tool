package in.baklavachi;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.IOException;

import java.net.URI;
import java.net.URL;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.Socket;
import java.net.UnknownHostException;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLPeerUnverifiedException;

public class SecurityCheckTool {

    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("Usage: java -jar security-check-tool.jar <url>");
            System.out.println("Example: java -jar security-check-tool.jar https://baklavachi.in");
            System.exit(1);
        }

        String urlStr = args[0].trim();
        if (!urlStr.startsWith("http://") && !urlStr.startsWith("https://")) {
            urlStr = "https://" + urlStr; // assume https if not provided
        }

        System.out.println("Running quick security checks for: " + urlStr);
        System.out.println("----------------------------------------------------");

        try {
            URI uri = URI.create(urlStr);
            performChecks(uri);
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }

    private static void performChecks(URI uri) throws Exception {
        checkScheme(uri);
        HttpResponse<String> response = fetch(uri);
        if (response != null) {
            checkSecurityHeaders(response);
            checkServerHeader(response);
            simpleHtmlSecretsScan(response.body());
        }
        checkRobots(uri);
        checkGitExposure(uri);
        checkTlsCertificate(uri);
        System.out.println("----------------------------------------------------");
        System.out.println("End of quick checks. These are passive checks — do not perform active intrusive tests without permission.");
    }

    private static void checkScheme(URI uri) {
        String scheme = uri.getScheme();
        if ("https".equalsIgnoreCase(scheme)) {
            System.out.println("[+] HTTPS: OK (site uses HTTPS)");
        } else {
            System.out.println("[-] HTTPS: MISSING (site does not use HTTPS)");
        }
    }

    private static HttpResponse<String> fetch(URI uri) {
        try {
            HttpClient client = HttpClient.newBuilder()
                    .followRedirects(HttpClient.Redirect.NORMAL)
                    .build();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(uri)
                    .GET()
                    .header("User-Agent", "SecurityCheckTool/1.0")
                    .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            System.out.println("[i] HTTP status: " + response.statusCode());
            return response;
        } catch (IOException | InterruptedException e) {
            System.out.println("[!] Error fetching URL: " + e.getMessage());
            return null;
        }
    }

    private static void checkSecurityHeaders(HttpResponse<String> response) {
        System.out.println("Checking common security headers:");
        Map<String, List<String>> headers = response.headers().map();

        checkHeader(headers, "content-security-policy", "Content-Security-Policy (CSP)");
        checkHeader(headers, "strict-transport-security", "Strict-Transport-Security (HSTS)");
        checkHeader(headers, "x-frame-options", "X-Frame-Options");
        checkHeader(headers, "x-content-type-options", "X-Content-Type-Options");
        checkHeader(headers, "referrer-policy", "Referrer-Policy");
        checkHeader(headers, "permissions-policy", "Permissions-Policy (formerly Feature-Policy)");
    }

    private static void checkHeader(Map<String, List<String>> headers, String key, String displayName) {
        if (headers.containsKey(key)) {
            System.out.println("  ✅ " + displayName + " found");
        } else {
            System.out.println("  ❌ " + displayName + " missing — suggestion: add this header to improve security");
        }
    }

    private static void checkServerHeader(HttpResponse<String> response) {
        Map<String, List<String>> headers = response.headers().map();
        if (headers.containsKey("server")) {
            System.out.println("[!] 'Server' header present. Leak: " + String.join(", ", headers.get("server")));
            System.out.println("    Suggestion: remove or obfuscate Server header to avoid exposing server software/version.");
        } else {
            System.out.println("[+] Server header not present (good).");
        }
    }

    private static void simpleHtmlSecretsScan(String body) {
        System.out.println("Simple HTML content scan for obvious keys:");
        if (body == null || body.isEmpty()) {
            System.out.println("  [i] No body to scan.");
            return;
        }

        List<String> patterns = Arrays.asList(
            "AKIA", // AWS-ish
            "AIza", // Google API key-ish
            "ssh-rsa", // private key in HTML
            "PRIVATE_KEY",
            "SECRET",
            "PASSWORD",
            "api_key",
            "apiKey"
        );

        String lower = body.toLowerCase();
        boolean found = false;
        for (String p : patterns) {
            if (lower.contains(p.toLowerCase())) {
                System.out.println("  [!] Found potential secret pattern: '" + p + "' in HTML. Manual review recommended.");
                found = true;
            }
        }
        if (!found) {
            System.out.println("  [+] Quick scan: no obvious secret patterns found in HTML (not a guarantee).");
        }
    }

    private static void checkRobots(URI uri) {
        try {
            URI robotsUri = uri.resolve("/robots.txt");
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest req = HttpRequest.newBuilder().uri(robotsUri).GET().build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
            System.out.println("robots.txt: HTTP " + resp.statusCode());
            if (resp.statusCode() == 200) {
                String content = resp.body();
                System.out.println("  robots.txt content length: " + content.length() + " chars");
                // Show small preview
                String preview = content.length() > 300 ? content.substring(0, 300) + "..." : content;
                System.out.println("  Preview:\n" + preview);
            } else {
                System.out.println("  robots.txt not found or inaccessible.");
            }
        } catch (Exception e) {
            System.out.println("  Error fetching robots.txt: " + e.getMessage());
        }
    }

    private static void checkGitExposure(URI uri) {
        try {
            URI gitHead = uri.resolve("/.git/HEAD");
            URI gitConfig = uri.resolve("/.git/config");

            HttpClient client = HttpClient.newHttpClient();
            HttpRequest reqHead = HttpRequest.newBuilder().uri(gitHead).GET().build();
            HttpResponse<String> rHead = client.send(reqHead, HttpResponse.BodyHandlers.ofString());

            if (rHead.statusCode() == 200 && rHead.body() != null && rHead.body().trim().length() > 0) {
                System.out.println("[!] Possible exposed .git/HEAD (HTTP 200). Content preview: " 
                    + (rHead.body().length() > 200 ? rHead.body().substring(0, 200) + "..." : rHead.body()));
                System.out.println("    Suggestion: ensure your .git folder is not served by your web server.");
                return;
            }

            HttpRequest reqCfg = HttpRequest.newBuilder().uri(gitConfig).GET().build();
            HttpResponse<String> rCfg = client.send(reqCfg, HttpResponse.BodyHandlers.ofString());
            if (rCfg.statusCode() == 200 && rCfg.body() != null && rCfg.body().trim().length() > 0) {
                System.out.println("[!] Possible exposed .git/config (HTTP 200). Preview: " 
                    + (rCfg.body().length() > 200 ? rCfg.body().substring(0, 200) + "..." : rCfg.body()));
                System.out.println("    Suggestion: remove .git from public directory or configure server to deny access.");
                return;
            }

            System.out.println("[+] .git folder does not appear exposed (quick check).");
        } catch (Exception e) {
            System.out.println("  Error checking .git exposure: " + e.getMessage());
        }
    }

    private static void checkTlsCertificate(URI uri) {
        try {
            if (!"https".equalsIgnoreCase(uri.getScheme())) {
                System.out.println("[TLS] Skipping TLS certificate check (not HTTPS).");
                return;
            }

            String host = uri.getHost();
            int port = (uri.getPort() == -1) ? 443 : uri.getPort();

            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            try (SSLSocket socket = (SSLSocket) factory.createSocket(host, port)) {
                socket.startHandshake();
                Certificate[] certs = socket.getSession().getPeerCertificates();
                if (certs.length > 0 && certs[0] instanceof X509Certificate) {
                    X509Certificate cert = (X509Certificate) certs[0];
                    Date notAfter = cert.getNotAfter();
                    Instant expiry = notAfter.toInstant();
                    DateTimeFormatter fmt = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
                            .withZone(ZoneId.systemDefault());
                    System.out.println("[TLS] Certificate subject: " + cert.getSubjectDN().getName());
                    System.out.println("[TLS] Issuer: " + cert.getIssuerDN().getName());
                    System.out.println("[TLS] Expires on: " + fmt.format(expiry));
                    long daysLeft = (notAfter.getTime() - System.currentTimeMillis()) / (1000L * 60 * 60 * 24);
                    if (daysLeft < 30) {
                        System.out.println("[!] Certificate expiry soon (" + daysLeft + " days). Renew ASAP if needed.");
                    } else {
                        System.out.println("[+] Certificate validity OK (" + daysLeft + " days left).");
                    }
                } else {
                    System.out.println("[TLS] No X509Certificate found or unexpected certificate type.");
                }
            } catch (SSLPeerUnverifiedException pe) {
                System.out.println("[TLS] Peer unverified: " + pe.getMessage());
            } catch (UnknownHostException uhe) {
                System.out.println("[TLS] Unknown host: " + uhe.getMessage());
            }
        } catch (Exception e) {
            System.out.println("[TLS] Error checking certificate: " + e.getMessage());
        }
    }
}
