package burp.DnsLogModule.ExtensionMethod;

import burp.Bootstrap.CustomHelpers;
import burp.Bootstrap.YamlReader;
import burp.DnsLogModule.ExtensionInterface.DnsLogAbstract;
import burp.IBurpExtenderCallbacks;
import com.github.kevinsawicki.http.HttpRequest;

public class DnsLogPrivate extends DnsLogAbstract {
    private IBurpExtenderCallbacks callbacks;

    private String dnslogDomainName;

    private YamlReader yamlReader;

    private String key;
    private String dnsDomain;
    private String Identifier;

    public DnsLogPrivate(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;

        this.yamlReader = YamlReader.getInstance(callbacks);
        this.dnslogDomainName = this.yamlReader.getString("dnsLogModule.other");

        this.setExtensionName("DnsLogPrivate");

        String other = this.yamlReader.getString("dnsLogModule.other");

        this.key = CustomHelpers.randomStr(8);
        this.dnsDomain = CustomHelpers.getParam(other, "DnsDomain").trim();
        this.Identifier = CustomHelpers.getParam(other, "Identifier").trim();

        this.init();
    }

    private void init() {
        if (this.dnsDomain == null || this.dnsDomain.length() <= 0) {
            throw new RuntimeException(String.format("%s 扩展-dnsDomain参数不能为空", this.getExtensionName()));
        }
        if (this.Identifier == null || this.Identifier.length() <= 0) {
            throw new RuntimeException(String.format("%s 扩展-Identifier参数不能为空", this.getExtensionName()));
        }

        String temporaryDomainName = this.key + "." + this.dnsDomain;
        this.setTemporaryDomainName(temporaryDomainName);
    }

    @Override
    public String getBodyContent() {
        String url = String.format("%s", this.Identifier);
        String userAgent = "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36";
        HttpRequest request = HttpRequest.get(url);
        request.trustAllCerts();
        request.trustAllHosts();
        request.followRedirects(false);
        request.header("User-Agent", userAgent);
        request.header("Accept", "*/*");
        request.readTimeout(30 * 1000);
        request.connectTimeout(30 * 1000);

        String body = request.body();

        if (!request.ok()) {
            throw new RuntimeException(
                    String.format(
                            "%s 扩展-%s内容有异常,异常内容: %s",
                            this.getExtensionName(),
                            this.dnslogDomainName,
                            body
                    )
            );
        }

        if (body == null) {
            return null;
        }
        return body;
    }

    @Override
    public String export() {
        return null;
    }

    @Override
    public void consoleExport() {

    }
}
