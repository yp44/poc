import com.google.gson.Gson;
import com.google.gson.stream.JsonReader;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

public class Poc_mscrm_oauth_3 {

    public final static int MAX_REDIRECT = 5;

    public final static int TEMPORARY_REDIRECT = 307;
    public final static int PERMANENT_REDIRECT = 308;

    public final static boolean FORCE_302_GET = false;

    public final static Map<String, String> default_headers = new HashMap();
    static{
        //default_headers.put("User-Agent", "JMozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0");
        //default_headers.put("Accept", "*/*");
    }

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


    private final static void addHeaders(RequestHttpContext requestContext, Map<String, List<String>> toHeaders) {
        final Map<String, String> headers = requestContext.getHeaders();
        toHeaders.entrySet().stream().forEach(e -> headers.put(e.getKey(), e.getValue().stream().collect(Collectors.joining("; "))));
    }

    private static void askCrm() throws IOException, InterruptedException {

        Map<String, String> headers = new HashMap<>();
        //headers.put("User-Agent", "JMozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0");
        //headers.put("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8");
        headers.putAll(default_headers);
        headers.put("Authorization", "Bearer " + TOKEN.access_token);

        RequestHttpContext req = new RequestHttpContext("GET",
                context.getMscrm_call(),
                Collections.emptyMap(),
                headers,
                true,
                50000,50000);


        ManagerHttpUrlConnection manager = new ManagerHttpUrlConnection(req);
        final ResponseHttpContext call = manager.call(FORCE_302_GET, new AtomicInteger(MAX_REDIRECT));


        System.out.println("===> " + call.getBody());
    }

    private static String askOAuthToken(Map<String, List<String>> toHeaders) throws IOException, InterruptedException {

        Map<String, String> headers = new HashMap<>();
        headers.putAll(default_headers);

        RequestHttpContext query = new RequestHttpContext("POST",
                OAUTH_URL,
                Collections.emptyMap(),
                new HashMap<>(),
                true,
                5000, 5000);

        StringBuilder body = new StringBuilder();
        body.append("grant_type=authorization_code&");
        body.append("code=" + CODE + "&");
        body.append("redirect_uri=" + URLEncoder.encode(redirect_uri));
        body.append("&client_id=" + client_id);

        query.setBodyContent(body.toString());
        System.out.println("Request Token Body : " + body.toString());

        ManagerHttpUrlConnection httpConnection = new ManagerHttpUrlConnection(query);
        final ResponseHttpContext call = httpConnection.call(FORCE_302_GET, new AtomicInteger(MAX_REDIRECT));

        final int status = call.getStatus();
        if (status != HttpURLConnection.HTTP_OK) {
            throw new IllegalStateException("Can't retrieve token, status is : " + status);
        }


        final String respBody = call.getBody();
        return respBody;
    }

    private static String encodeValue(String value) throws UnsupportedEncodingException {
        return URLEncoder.encode(value, StandardCharsets.UTF_8.toString());
    }

    private static Map<String, List<String>> sendAuthenticationForm(Map<String, List<String>> toHeaders) throws IOException, InterruptedException {

        Map<String, String> params = new HashMap();
        params.put("resource", resource);
        params.put("response_type", response_type);
        params.put("state", "");
        params.put("client_id", client_id);
        params.put("scope", "");
        params.put("redirect_uri", redirect_uri);

        Map<String, String> headers = new HashMap();
        //headers.put("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Postman/7.33.1 Chrome/78.0.3904.130 Electron/7.3.2 Safari/537.36");
        //headers.put("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3");
        headers.putAll(default_headers);

        RequestHttpContext queryContext = new RequestHttpContext("POST",
                AUTHORIZE_URL,
                params,
                headers,
                false,
                5000, 5000);

        StringBuilder post = new StringBuilder("UserName=");
        post.append(encodeValue(LOGIN));
        post.append("&Password=");
        post.append(encodeValue(PWD));
        post.append("&AuthMethod=FormsAuthentication");
        queryContext.setBodyContent(post.toString());


        ManagerHttpUrlConnection connHttp = new ManagerHttpUrlConnection(queryContext);
        final ResponseHttpContext call = connHttp.call(FORCE_302_GET, new AtomicInteger(MAX_REDIRECT));

        return getHeaders(call.getHeaders(), "Set-Cookie");
    }



    private static boolean extractCode(ResponseHttpContext response) {
        final Optional<String> optLocation = response.getFirstValueHeader("Location");
        if (!optLocation.isPresent()) {
            return false;
        }
        final String[] split = optLocation.get().split("&|\\?");
        final Optional<String> optCode = List.of(split).stream().filter(e -> e.startsWith("code=")).findFirst();

        if (optCode.isPresent()) {
            CODE = optCode.get().substring(5);
            System.out.println("CODE found : " + CODE);
            return true;
        }
        else{
            System.out.println("Code not found in " + response.getFirstValueHeader("Location"));
        }
        return false;
    }

    public final static class ResponseHttpContext {
        private int status;
        private Map<String, List<String>> headers;
        private String body;

        public static ResponseHttpContext fromHttpUrlConnection(HttpURLConnection conn) throws IOException {
            final int status = conn.getResponseCode();
            final Map<String, List<String>> respHeaders = conn.getHeaderFields();

            ResponseHttpContext context = new ResponseHttpContext(status);
            context.setHeaders(respHeaders);

            try(BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream(), "UTF-8"))){
                final String body = in.lines().collect(Collectors.joining("\n"));
                context.setBody(body);
            }

            return context;
        }

        public ResponseHttpContext(int status) {
            this.status = status;
        }

        public int getStatus() {
            return status;
        }

        public void setStatus(int status) {
            this.status = status;
        }

        public Map<String, List<String>> getHeaders() {
            return headers;
        }

        public void setHeaders(Map<String, List<String>> headers) {
            this.headers = headers;
        }

        private Optional<List<String>> _getAllValuesHeader(String key) {
            if (this.getHeaders() == null || this.getHeaders().size() <= 0) {
                return Optional.empty();
            }

            if (!this.getHeaders().containsKey(key)) {
                return Optional.empty();
            }

            return Optional.ofNullable(this.getHeaders().get(key));
        }

        public Optional<List<String>> getAllValuesHeader(String key) {
            String keyUpper = ("" + key.charAt(0)).toUpperCase() + key.substring(1);
            String keyLower = ("" + key.charAt(0)).toLowerCase() + key.substring(1);

            Optional<List<String>> values = _getAllValuesHeader(keyUpper);
            if(values.isEmpty()){
                values = _getAllValuesHeader(keyLower);
            }

            return values;
        }

        private Optional<String> getFirstValueHeader(String key) {
            final Optional<List<String>> values = getAllValuesHeader(key);
            if(!values.isPresent()){
                return Optional.empty();
            }

            final List<String> ss = values.get();
            if(ss.size() <= 0){
                return Optional.empty();
            }

            return Optional.ofNullable(ss.get(0));
        }

        public String getBody() {
            return body;
        }

        public void setBody(String body) {
            this.body = body;
        }
    }

    public final static class RequestHttpContext {

        private String method;
        private String base;
        private Map<String, String> params;
        private Map<String, String> headers;
        private boolean followRedirects;
        private int connectionTimeout;
        private int readTimeout;
        private String bodyContent = "";

        public RequestHttpContext(String method, String base, Map<String, String> params, Map<String, String> headers, boolean followRedirects, int connectionTimeout, int readTimeout) {
            this.method = method;
            this.base = base;
            this.params = params;
            this.headers = headers;
            this.followRedirects = followRedirects;
            this.connectionTimeout = connectionTimeout;
            this.readTimeout = readTimeout;
        }

        public String getBodyContent() {
            return bodyContent;
        }

        public void setBodyContent(String bodyContent) {
            this.bodyContent = bodyContent;
        }

        public String getMethod() {
            return method;
        }

        public void setMethod(String method) {
            this.method = method;
        }

        public String getBase() {
            return base;
        }

        public void setBase(String base) {
            this.base = base;
        }

        public Map<String, String> getParams() {
            return params;
        }

        public void setParams(Map<String, String> params) {
            this.params = params;
        }

        public Map<String, String> getHeaders() {
            return headers;
        }

        public void setHeaders(Map<String, String> headers) {
            this.headers = headers;
        }

        public boolean isFollowRedirects() {
            return followRedirects;
        }

        public void setFollowRedirects(boolean followRedirects) {
            this.followRedirects = followRedirects;
        }

        public int getConnectionTimeout() {
            return connectionTimeout;
        }

        public void setConnectionTimeout(int connectionTimeout) {
            this.connectionTimeout = connectionTimeout;
        }

        public int getReadTimeout() {
            return readTimeout;
        }

        public void setReadTimeout(int readTimeout) {
            this.readTimeout = readTimeout;
        }
    }

    public final static class ManagerHttpUrlConnection{

        private RequestHttpContext requestHttpContext;

        public ManagerHttpUrlConnection(RequestHttpContext requestHttpContext) {
            this.requestHttpContext = requestHttpContext;
        }

        public ResponseHttpContext call(boolean force302Get, AtomicInteger atomicInteger) throws IOException, InterruptedException {
            final HttpURLConnection conn = buildUrl(requestHttpContext);

            if("POST".equals(conn.getRequestMethod())) {
                conn.setDoOutput(true);
                try (DataOutputStream dos = new DataOutputStream(conn.getOutputStream())) {
                    final byte[] form = requestHttpContext.getBodyContent().getBytes(StandardCharsets.UTF_8);
                    dos.write(form);
                    dos.flush();
                }
            }
            else{
                conn.connect();
            }

            final ResponseHttpContext respContext = ResponseHttpContext.fromHttpUrlConnection(conn);
            return followRedirect(requestHttpContext, respContext, force302Get, atomicInteger);
        }

        private ResponseHttpContext followRedirect(RequestHttpContext queryContext, ResponseHttpContext respContext, boolean force_get_302, AtomicInteger nbRedirect) throws IOException, InterruptedException {
            final int nbR = nbRedirect.decrementAndGet();
            final int status = respContext.getStatus();

            boolean redirect = false;
            if (status != HttpURLConnection.HTTP_OK && ((status == HttpURLConnection.HTTP_MOVED_TEMP
                    || status == HttpURLConnection.HTTP_MOVED_PERM || status == HttpURLConnection.HTTP_SEE_OTHER
                    || status == TEMPORARY_REDIRECT || status == PERMANENT_REDIRECT))) {
                redirect = true;
            }


            //final HttpHeaders headers = resp.headers();
            final Optional<String> location = respContext.getFirstValueHeader("location");


            if (!redirect || !location.isPresent() || nbR <= 0) {
                System.out.println("NO REDIRECT : Redirect=" + redirect + " / Location=" + location.isPresent() + " / Nb Redirect=" + nbR);
                return respContext;
            }

            System.out.println("Redirect to : " + location.get());

            queryContext.setBase(location.get());
            queryContext.setParams(Collections.emptyMap());


            final List<String> cookie = respContext.getAllValuesHeader("Set-Cookie").orElse(Collections.emptyList());
            if (cookie.size() > 0) {
                final String collect = cookie.stream().collect(Collectors.joining("; "));
                queryContext.getHeaders().put("Cookie", collect);
            }

            if (force_get_302) {
                queryContext.setMethod("GET");
                queryContext.setBodyContent("");
            }

            boolean found = extractCode(respContext);
            if(found){
                return respContext;
            }

            ManagerHttpUrlConnection manager = new ManagerHttpUrlConnection(queryContext);
            final ResponseHttpContext redirectResponseContext = manager.call(force_get_302, nbRedirect);


            return redirectResponseContext;
        }

        private HttpURLConnection buildUrl(RequestHttpContext context) throws IOException {
            StringBuilder sb = new StringBuilder(context.getBase());

            if (context.getParams().size() > 0) {
                sb.append("?");

                boolean first = true;
                for (Map.Entry<String, String> e : context.getParams().entrySet()) {
                    if (!first) {
                        sb.append("&");
                    }
                    first = false;
                    sb.append(e.getKey());
                    sb.append("=");
                    sb.append(encodeValue(e.getValue()));
                }
            }

            URL url = new URL(sb.toString());
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();

            if (context.getHeaders().size() > 0) {
                for (Map.Entry<String, String> e : context.getHeaders().entrySet()) {
                    //conn.setRequestProperty(e.getKey(), encodeValue(e.getValue()));
                    conn.setRequestProperty(e.getKey(), e.getValue());
                }
            }

            conn.setRequestMethod(context.getMethod());

            conn.setInstanceFollowRedirects(context.isFollowRedirects());
            conn.setConnectTimeout(context.getConnectionTimeout());
            conn.setReadTimeout(context.getReadTimeout());

            return conn;
        }

        public RequestHttpContext getRequestHttpContext() {
            return requestHttpContext;
        }
    }

}
