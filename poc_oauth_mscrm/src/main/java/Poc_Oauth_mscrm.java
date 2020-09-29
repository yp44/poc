import com.microsoft.aad.adal4j.AuthenticationCallback;
import com.microsoft.aad.adal4j.AuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationResult;
import io.mikael.urlbuilder.UrlBuilder;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.CookieHandler;
import java.net.CookieManager;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.LocalDate;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class Poc_Oauth_mscrm {

    public static LoadContext context = LoadContext.load();

    public final static String LOGIN = context.getLOGIN();
    public final static String PWD = context.getPWD();
    public final static String AUTHORIZE_URL = context.getAUTHORIZE_URL();
    public final static String OAUTH_URL = context.getOAUTH_URL();
    public final static String resource = context.getResource();
    public final static String response_type = context.getResponse_type();
    public final static String client_id = context.getClient_id();
    public final static String redirect_uri = context.getRedirect_uri();


    public static void main(String[] args) {
        //adal4j();
        manualCall();
    }

    public static void adal4j() {

        try {
            ExecutorService service = Executors.newFixedThreadPool(1);
            final AuthenticationContext authenticationContext = new AuthenticationContext(AUTHORIZE_URL, false, service);
            final Future<AuthenticationResult> authenticationResultFuture = authenticationContext.acquireToken(resource, client_id, LOGIN, PWD, new AuthenticationCallback() {
                @Override
                public void onSuccess(Object result) {
                    System.out.println("SUCCESS");
                }

                @Override
                public void onFailure(Throwable exc) {
                    System.out.println("FAILURE");
                }
            });

            final String accessToken = authenticationResultFuture.get().getAccessToken();
            System.out.println("END");

        } catch (MalformedURLException | InterruptedException | ExecutionException e) {
            e.printStackTrace();
        }

    }

    private static String encodeValue(String value) throws UnsupportedEncodingException {
        return URLEncoder.encode(value, StandardCharsets.UTF_8.toString());
    }

    public static void manualCall() {
        try {

            URI authorize_uri = UrlBuilder.fromString(AUTHORIZE_URL)
                    .addParameter("resource", resource)
                    .addParameter("response_type", response_type)
                    .addParameter("client_id", client_id)
                    .addParameter("redirect_uri", redirect_uri)
                    .toUri();


            HttpClient client = HttpClient.newBuilder()
                    .followRedirects(HttpClient.Redirect.NEVER)
                    .build();


            final HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(authorize_uri)
                    .timeout(Duration.ofMinutes(2))
                    .setHeader("User-Agent", "JMozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0")
                    .setHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
                    .POST(HttpRequest.BodyPublishers.ofString("UserName=" + encodeValue(LOGIN) + "&Password=" + encodeValue(PWD) + "&AuthMethod=FormsAuthentication"));

            HttpRequest requestA = requestBuilder.build();

            final HttpResponse<String> response = client.send(requestA, HttpResponse.BodyHandlers.ofString());
            final String body = response.body();
            final HttpHeaders headersA = response.headers();
            System.out.println("=> " + headersA.firstValue("location"));

            final String locationB = headersA.firstValue("location").get();
            final String cookieB = headersA.firstValue("set-cookie").get();
            final HttpRequest.Builder builderB = requestBuilder.copy().GET().uri(URI.create(locationB))
                    .header("Cookie", cookieB);


            final HttpRequest requestB = builderB.build();

            final HttpResponse<String> responseB = client.send(requestB, HttpResponse.BodyHandlers.ofString());

            final String bodyB = responseB.body();
            final HttpHeaders headersB = responseB.headers();
            final String locationC = headersB.firstValue("location").get();
            final URI uri = URI.create(locationC);
            final String rawQuery = uri.getRawQuery();
            String code = null;
            if (rawQuery.startsWith("code=")) {
                code = rawQuery.substring(5);
                code = code.substring(0, code.indexOf("&client-request"));
            }
            System.out.println("CODE = " + code);


            HttpClient clientOauth = HttpClient.newBuilder().build();

            URI oauth_uri = UrlBuilder.fromString(OAUTH_URL)
                    .addParameter("client_id", client_id)
                    .addParameter("code", code)
                    .addParameter("redirect_uri", redirect_uri)
                    .addParameter("grant_type", "authorization_code")
                    .toUri();

            final HttpRequest.Builder reqBuilderOAuth = HttpRequest.newBuilder()
                    .uri(oauth_uri)
                    .timeout(Duration.ofMinutes(2))
                    .setHeader("User-Agent", "JMozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0")
                    .setHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
                    .POST(HttpRequest.BodyPublishers.noBody());

            final String cookieOauth = headersB.firstValue("set-cookie").get();
            reqBuilderOAuth.header("Cookie", cookieB);

            final HttpResponse<String> responseOAuth = clientOauth.send(reqBuilderOAuth.build(), HttpResponse.BodyHandlers.ofString());
            System.out.println("===> " + responseOAuth.body());


            HttpClient clientCrm = HttpClient.newBuilder().build();

            final HttpRequest.Builder reqBuilderCrm = HttpRequest.newBuilder()
                    .uri(URI.create(context.getMscrm_call()))
                    .timeout(Duration.ofMinutes(2))
                    .setHeader("User-Agent", "JMozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0")
                    .setHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
                    .GET()
                    .setHeader("Authorization", "Bearer " + code);
            final HttpRequest requestCrm = reqBuilderCrm.build();

            final HttpResponse<String> responseCRM = clientCrm.send(requestCrm, HttpResponse.BodyHandlers.ofString());
            System.out.println("===> " + responseCRM.body());


        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }

    }

}
