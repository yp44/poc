import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class LoadContext {

    public final static String context_file = System.getProperty("load_context_file", "/tmp/context.prop");

    private String LOGIN;
    private String PWD;
    private String AUTHORIZE_URL;
    private String OAUTH_URL;
    private String resource;
    private String response_type;
    private String client_id;
    private String redirect_uri;
    private String mscrm_call;

    private LoadContext(){}

    public static LoadContext load() {
        LoadContext c = new LoadContext();

        try(InputStream in = new FileInputStream(context_file)){
            Properties p = new Properties();
            p.load(in);

            c.setLOGIN(p.getProperty("LOGIN"));
            c.setPWD(p.getProperty("PWD"));
            c.setAUTHORIZE_URL(p.getProperty("AUTHORIZE_URL"));
            c.setOAUTH_URL(p.getProperty("OAUTH_URL"));
            c.setResource(p.getProperty("resource"));
            c.setResponse_type(p.getProperty("response_type"));
            c.setClient_id(p.getProperty("client_id"));
            c.setRedirect_uri(p.getProperty("redirect_uri"));
            c.setMscrm_call(p.getProperty("mscrm_call"));
        }
        catch (IOException e){
            System.err.println("Can't load context : " + context_file + " : " + e.getMessage());
            e.printStackTrace(System.err);
            System.exit(1);
        }

        return c;
    }

    public String getLOGIN() {
        return LOGIN;
    }

    public void setLOGIN(String LOGIN) {
        this.LOGIN = LOGIN;
    }

    public String getPWD() {
        return PWD;
    }

    public void setPWD(String PWD) {
        this.PWD = PWD;
    }

    public String getAUTHORIZE_URL() {
        return AUTHORIZE_URL;
    }

    public void setAUTHORIZE_URL(String AUTHORIZE_URL) {
        this.AUTHORIZE_URL = AUTHORIZE_URL;
    }

    public String getOAUTH_URL() {
        return OAUTH_URL;
    }

    public void setOAUTH_URL(String OAUTH_URL) {
        this.OAUTH_URL = OAUTH_URL;
    }

    public String getResource() {
        return resource;
    }

    public void setResource(String resource) {
        this.resource = resource;
    }

    public String getResponse_type() {
        return response_type;
    }

    public void setResponse_type(String response_type) {
        this.response_type = response_type;
    }

    public String getClient_id() {
        return client_id;
    }

    public void setClient_id(String client_id) {
        this.client_id = client_id;
    }

    public String getRedirect_uri() {
        return redirect_uri;
    }

    public void setRedirect_uri(String redirect_uri) {
        this.redirect_uri = redirect_uri;
    }

    public String getMscrm_call() {
        return mscrm_call;
    }

    public void setMscrm_call(String mscrm_call) {
        this.mscrm_call = mscrm_call;
    }
}
