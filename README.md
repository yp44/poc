To run mscrm POC:

Create a `/tmp/context.prop` file containing:
```
LOGIN=xxxx
PWD=yyyy
AUTHORIZE_URL=https://xxxxxxx/adfs/oauth2/authorize
OAUTH_URL=https://xxxxxx/adfs/oauth2/token
resource=https://xxxxxx/
response_type=code
client_id=zzzzzz
redirect_uri=https://zzzzz
mscrm_call=https://xxxxxxx/api/data/v8.2/accountleadscollection
```
And then exec
```
mvn clean install -pl poc_oauth_mscrm
mvn exec:java -pl poc_oauth_mscrm
```