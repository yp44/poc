import com.google.gson.Gson;
import com.google.gson.stream.JsonReader;
import io.mikael.urlbuilder.UrlBuilder;

import java.io.IOException;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

public class Poc_mscrm_oauth_2 {

    public final static int MAX_REDIRECT = 5;

    public final static int TEMPORARY_REDIRECT = 307;
    public final static int PERMANENT_REDIRECT = 308;

    public final static boolean FORCE_302_GET = true;

    public static LoadContext context = LoadContext.load();

    public final static String LOGIN = context.getLOGIN();
    public final static String PWD = context.getPWD();
    public final static String AUTHORIZE_URL = context.getAUTHORIZE_URL();
    public final static String OAUTH_URL = context.getOAUTH_URL();
    public final static String resource = context.getResource();
    public final static String response_type = context.getResponse_type();
    public final static String client_id = context.getClient_id();
    public final static String redirect_uri = context.getRedirect_uri();


    private static String CODE = null;
    private static Token TOKEN = null;

    private final static class Token {
        String access_token;
        String token_type;
        Long expires_in;
    }


    public final static void main(String[] args) throws IOException, InterruptedException {

        boolean exec = true;

        if (exec) {
            Map<String, List<String>> form = new HashMap<>();
            //form = getForm();

            System.out.println("*************** Get authentication Code *******************");
            final Map<String, List<String>> authentication = sendAuthenticationForm(form);
            System.out.println("*************** Get OAuth Token *******************");
            final String json = askOAuthToken(authentication);


            Gson gson = new Gson();
            JsonReader jsr = new JsonReader(new StringReader(json));
            TOKEN = gson.fromJson(jsr, Token.class);

            System.out.println("TOKEN : " + TOKEN.access_token);
            System.out.println("*************** Call Crm *******************");
            askCrm();
        }


    }

    private static String getClientIdBase64() {
        return new String(Base64.getEncoder().encode((client_id + ":").getBytes()));
    }

    private final static Map<String, List<String>> getHeaders(Map<String, List<String>> headers, String... keys) {
        Map<String, List<String>> maps = new HashMap<>();

        for (int i = 0; i < keys.length; i++) {
            if (headers.containsKey(keys[i])) {
                maps.put(keys[i], headers.get(keys[i]));
            }
        }

        return maps;
    }

    private final static void addHeaders(HttpRequest.Builder requestBuilder, Map<String, List<String>> toHeaders) {
        toHeaders.entrySet().stream().forEach(e -> requestBuilder.setHeader(e.getKey(), e.getValue().stream().collect(Collectors.joining("; "))));
    }

    private static void askCrm() throws IOException, InterruptedException {
        HttpClient clientCrm = HttpClient.newBuilder().build();

        final HttpRequest.Builder reqBuilderCrm = HttpRequest.newBuilder()
                .uri(URI.create(context.getMscrm_call()))
                .timeout(Duration.ofMinutes(2))
                .setHeader("User-Agent", "JMozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0")
                .setHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
                .GET()
                .setHeader("Authorization", "Bearer " + TOKEN.access_token);
        final HttpRequest requestCrm = reqBuilderCrm.build();

        final HttpResponse<String> responseCRM = clientCrm.send(requestCrm, HttpResponse.BodyHandlers.ofString());
        System.out.println("===> " + responseCRM.body());
    }

    private static String askOAuthToken(Map<String, List<String>> toHeaders) throws IOException, InterruptedException {
        URI oauth_uri = UrlBuilder.fromString(OAUTH_URL)
                .toUri();

        HttpClient client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();

        StringBuilder body = new StringBuilder();
        body.append("grant_type=authorization_code&");
        body.append("code=" + CODE + "&");
        body.append("redirect_uri=" + URLEncoder.encode(redirect_uri) + "&");
        body.append("client_id=" + client_id);

        System.out.println("Request Token Body : " + body.toString());

        final HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(oauth_uri)
                .timeout(Duration.ofMinutes(2))
                .setHeader("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Postman/7.33.1 Chrome/78.0.3904.130 Electron/7.3.2 Safari/537.36")
                .setHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3")
                .setHeader("Authorization", "Basic " + getClientIdBase64())
                .POST(HttpRequest.BodyPublishers.ofString(body.toString()));

        addHeaders(requestBuilder, toHeaders);

        HttpResponse<String> response = client.send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString());
        response = followRedirect(response, client, requestBuilder.copy(), FORCE_302_GET, new AtomicInteger(MAX_REDIRECT));

        final int status = response.statusCode();
        if (status != HttpURLConnection.HTTP_OK) {
            throw new IllegalStateException("Can't retrieve token, status is : " + status);
        }


        final String respBody = response.body();
        return respBody;
    }

    private static String encodeValue(String value) throws UnsupportedEncodingException {
        return URLEncoder.encode(value, StandardCharsets.UTF_8.toString());
    }

    private static Map<String, List<String>> sendAuthenticationForm(Map<String, List<String>> toHeaders) throws IOException, InterruptedException {
        URI authorize_uri = UrlBuilder.fromString(AUTHORIZE_URL)
                .addParameter("resource", resource)
                .addParameter("response_type", response_type)
                .addParameter("state", "")
                .addParameter("client_id", client_id)
                .addParameter("scope", "")
                .addParameter("redirect_uri", redirect_uri)
                .toUri();

        HttpClient client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();

        final HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(authorize_uri)
                .timeout(Duration.ofMinutes(2))
                .setHeader("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Postman/7.33.1 Chrome/78.0.3904.130 Electron/7.3.2 Safari/537.36")
                .setHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3")
                //.setHeader("Referer", authorize_uri.toASCIIString())
                .POST(HttpRequest.BodyPublishers.ofString("UserName=" + encodeValue(LOGIN) + "&Password=" + encodeValue(PWD) + "&AuthMethod=FormsAuthentication"));

        addHeaders(requestBuilder, toHeaders);

        HttpResponse<String> response = client.send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString());
        response = followRedirect(response, client, requestBuilder.copy(), FORCE_302_GET, new AtomicInteger(MAX_REDIRECT));

        final String body = response.body();
        final HttpHeaders headers = response.headers();


        return getHeaders(headers.map(), "Set-Cookie");
    }

    private static HttpResponse<String> followRedirect(HttpResponse<String> resp, HttpClient client, HttpRequest.Builder requestBuilder, boolean force_get_302, AtomicInteger nbRedirect) throws IOException, InterruptedException {
        final int status = resp.statusCode();
        final int nbR = nbRedirect.decrementAndGet();

        boolean redirect = false;
        if (status != HttpURLConnection.HTTP_OK && ((status == HttpURLConnection.HTTP_MOVED_TEMP
                || status == HttpURLConnection.HTTP_MOVED_PERM || status == HttpURLConnection.HTTP_SEE_OTHER
                || status == TEMPORARY_REDIRECT || status == PERMANENT_REDIRECT))) {
            redirect = true;
        }


        final HttpHeaders headers = resp.headers();
        final Optional<String> location = headers.firstValue("location");
        ;
        if (!redirect || !location.isPresent() || nbR <= 0) {
            System.out.println("NO REDIRECT : Redirect=" + redirect + " / Location=" + location.isPresent() + " / Nb Redirect=" + nbR);
            return resp;
        }

        System.out.println("Redirect to : " + location.get());

        requestBuilder.uri(URI.create(location.get()));

        final List<String> cookie = headers.allValues("set-cookie");
        if (cookie.size() > 0) {
            requestBuilder.setHeader("Cookie", cookie.stream().collect(Collectors.joining("; ")));
        }

        if (force_get_302) {
            requestBuilder.GET();
        }

        HttpResponse<String> response = client.send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString());

        final boolean found = extractCode(response);
        if(found){
            return response;
        }

        return followRedirect(response, client, requestBuilder.copy(), force_get_302, nbRedirect);
    }

    private static boolean extractCode(HttpResponse<String> response) {
        final Optional<String> optLocation = response.headers().firstValue("Location");
        if (!optLocation.isPresent()) {
            return false;
        }
        final String[] split = optLocation.get().split("&|\\?");
        final Optional<String> optCode = List.of(split).stream().filter(e -> e.startsWith("code=")).findFirst();

        if (optCode.isPresent()) {
            CODE = optCode.get().substring(5);
            return true;
        }

        return false;
    }


    private static Map<String, List<String>> getForm() throws IOException, InterruptedException {
        URI authorize_uri = UrlBuilder.fromString(AUTHORIZE_URL)
                .addParameter("resource", resource)
                .addParameter("response_type", response_type)
                .addParameter("state", "")
                .addParameter("client_id", client_id)
                .addParameter("scope", "")
                .addParameter("redirect_uri", redirect_uri)
                .toUri();

        HttpClient client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();

        final HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(authorize_uri)
                .timeout(Duration.ofMinutes(2))
                .setHeader("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Postman/7.33.1 Chrome/78.0.3904.130 Electron/7.3.2 Safari/537.36")
                .setHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3")
                .GET();

        final HttpResponse<String> response = client.send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString());

        final String body = response.body();
        final HttpHeaders headers = response.headers();

        return getHeaders(headers.map(), "Set-Cookie");
    }

}
