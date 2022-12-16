package burp.Bootstrap;

import java.io.StringReader;
import java.util.List;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import burp.*;
import burp.UI.Tags;
import com.alibaba.fastjson.JSON;
import org.dom4j.DocumentHelper;

public class BurpAnalyzedRequest {
    private IBurpExtenderCallbacks callbacks;

    private IExtensionHelpers helpers;

    private CustomBurpUrl customBurpUrl;

    private CustomBurpHelpers customBurpHelpers;

    private List<IParameter> equalParameters = new ArrayList<>();
    private List<IParameter> JsonXmlFileParameters = new ArrayList<>();
    private List<IParameter> URLParameters = new ArrayList<>();

    private IHttpRequestResponse requestResponse;

    private Tags tags;

    public BurpAnalyzedRequest(IBurpExtenderCallbacks callbacks, Tags tags, IHttpRequestResponse requestResponse) {
        this.callbacks = callbacks;
        this.helpers = this.callbacks.getHelpers();

        this.tags = tags;

        this.customBurpHelpers = new CustomBurpHelpers(callbacks);
        this.requestResponse = requestResponse;
        this.customBurpUrl = new CustomBurpUrl(this.callbacks , requestResponse);

        initParameters();
        initJsonXmlFileParameters();
        initURLParameters();
//        initEligibleJsonParameters();
    }

    public IHttpRequestResponse requestResponse() {
        return this.requestResponse;
    }

    public IRequestInfo analyzeRequest() {
        return this.helpers.analyzeRequest(this.requestResponse.getRequest());
    }

    /**
     * 初始化非json、xml、xml_attr、multi、cookie参数
     */
    private void initParameters() {
        if (analyzeRequest().getParameters().isEmpty()) {
            return;
        }

        for (IParameter p : analyzeRequest().getParameters()) {
            // 类型为json、xml、xml_attr、cookie、multi不加入
            if (p.getType() == 6 || p.getType() == 3 || p.getType() == 4 || p.getType() == 2 || p.getType() == 5) {
                continue;
            }
            if (p.getName() == null || "".equals(p.getName())) {
                continue;
            }
            this.equalParameters.add(p);
        }
    }

    /**
     * 初始化非cookie、xml_attr、equal参数
     */
    private void initJsonXmlFileParameters() {
        if (analyzeRequest().getParameters().isEmpty()) {
            return;
        }

        for (IParameter p : analyzeRequest().getParameters()) {
            // 类型为cookie、xml_attr、url不加入
            if (p.getType() == 2 || p.getType() == 4 || p.getType() == 1 || p.getType() == 0) {
                continue;
            }
            if (p.getName() == null || "".equals(p.getName())) {
                continue;
            }
            this.JsonXmlFileParameters.add(p);
        }
    }

    /**
     * 初始化URL中的参数
     */
    private void initURLParameters() {
        if (analyzeRequest().getParameters().isEmpty()) {
            return;
        }
        for (IParameter p : analyzeRequest().getParameters()) {
            // 类型为非URL参数不加入
            if (p.getType() != 0) {
                continue;
            }
            if (p.getName() == null || "".equals(p.getName())) {
                continue;
            }
            this.URLParameters.add(p);
        }
    }



    /**
     * 解析json字符串，普通和嵌套类型都可
     *
     * @param jsonData 请求包的json数据
     * @param payload  textshell的payload
     * @return 返回添加payload的json字符串
     */
    public String  analyseJson(String jsonData , String payload, String dnsLog) {
        String jsonResult = "";
        int paramNumber = 1;
        boolean j = false;
        for(int i=1;i<jsonData.length();i++){
            if(j&&jsonData.charAt(i) == '"'){
                j = false;
                continue;
            }
            if(j){
                continue;
            }
            if(jsonData.charAt(i) == '"'&&jsonData.charAt(i-1) == ':'){
                jsonResult = jsonResult + "\"" + payload.replace("dns-url",
                        (paramNumber++) + "." + "json" + "." + dnsLog) + "\"";
                j = true;
            }else{
                jsonResult = jsonResult + jsonData.charAt(i);
            }

        }
        return jsonResult;
    }

    /**
     * 解析XML字符串
     *
     * @param XMLData
     * @param payload
     * @param dnsLog
     * @return 返回添加了payload的字符串
     */
    public String analyseXML(String XMLData, String payload, String dnsLog){
        List<String> list = new ArrayList<String>();
        Pattern pattern = Pattern.compile(">(.*?)</");
        Matcher m = pattern.matcher(XMLData);
        int paramNumber = 1;
        while (m.find()) {
            list.add(m.group(1));
        }
        for (String str: list){
            XMLData = XMLData.replace(">" + str + "</",
                    ">" + payload.replace("dns-url",
                            (paramNumber++) + "." + "xml" + "." + dnsLog) + "</");
        }
        return XMLData;
    }

    /**
     * 获取所有符合条件的URL参数
     *
     * @return
     */
    public List<IParameter> getURLParameters() {
        return  this.URLParameters;
    }

    /**
     * 获取所有的equal参数
     *
     * @return List<IParameter>
     */
    public List<IParameter> getEqualParameters() {
        return this.equalParameters;
    }


    /**
     * 获取所有符合条件的json、XML参数
     *
     * @return List<IParameter>
     */
    public List<IParameter> getJsonXmlFileParameters() {
        return this.JsonXmlFileParameters;
    }

    /**
     * 判断请求参数内容是否有Json
     *
     * @return boolean
     */
    public boolean isRequestParameterContentJson() {
        if (CustomHelpers.isJson(this.customBurpHelpers.getHttpRequestBody(requestResponse().getRequest()))) {
            return true;
        }
        if (getEqualParameters().isEmpty()) {
            return false;
        }
        return true;
    }


    /**
     * 会根据程序类型自动组装请求的 请求发送接口
     */
    public IHttpRequestResponse makeHttpRequest(String payload, String dnsLogUrl) {
        byte[] newRequest;

        byte[] request = this.requestResponse.getRequest();

        if(this.customBurpUrl.getRequestQuery() != null && this.customBurpHelpers.getHttpRequestBody(request) != null) {
            byte[] URLRequest = this.buildURLParameter(payload, dnsLogUrl);
            IHttpRequestResponse urlHttpRequestResponse = this.callbacks.makeHttpRequest(this.requestResponse().getHttpService(),URLRequest);
            switch (this.analyzeRequest().getContentType()){
                case 1:
                    newRequest = this.buildEqualParameter(payload, dnsLogUrl);
                    break;
                case 2:
                    newRequest = this.buildFileParameter(payload, dnsLogUrl);
                    break;
                default:
                    newRequest = this.buildParameter(payload, dnsLogUrl);
            }
        } else {
            switch (this.analyzeRequest().getContentType()){
                case 1:
                    newRequest = this.buildEqualParameter(payload, dnsLogUrl);
                    break;
                case 2:
                    newRequest = this.buildFileParameter(payload, dnsLogUrl);
                    break;
                default:
                    newRequest = this.buildParameter(payload, dnsLogUrl);
            }
        }

        IHttpRequestResponse newHttpRequestResponse = this.callbacks.makeHttpRequest(this.requestResponse().getHttpService(), newRequest);
        return newHttpRequestResponse;
    }



    /**
     * 判断字符串为JSON格式
     *
     * @param str 参数的value或者POST包的body
     * @return 是=true 否=flase
     */
    public Integer isJSONOrXML(String str) {
        try {
            JSON.parse(str.replaceAll("(\\[(.*?)])","\"test\""));
            return 1;
        } catch (Exception e) {
        }
        try {
            DocumentHelper.parseText(str);
            return 2;
        } catch (Exception e) {
        }

        return 0;
    }

    /**
     * 获取特征key
     *
     * @return
     */
    public String getKey(){
        String key = this.helpers.analyzeRequest(this.requestResponse).getMethod() + "."
                + this.customBurpUrl.getRequestHost() + "."
                + this.customBurpUrl.getRequestPort()
                + this.customBurpUrl.getRequestPath().replace("/",".");
        return key;
    }


    /**
     * json数据格式请求处理方法
     *
     * @param payload
     * @return
     */
    private byte[] buildHttpMessage(String payload) {
        byte[] newRequest = this.helpers.buildHttpMessage(
                this.analyzeRequest().getHeaders(),
                this.helpers.stringToBytes(payload));
        return newRequest;
    }

    /**
     * 构造request header的payload
     *
     * @param payload
     * @param dnsLog
     * @return
     */
    private List<String> getHeaders(String payload, String dnsLog) {
        List<String> headers = this.analyzeRequest().getHeaders();
        int paramNumber = 1;

        for(int i =1; i<headers.size();i++){
            if(headers.get(i).contains("User-Agent:") || headers.get(i).contains("token:") ||
                    headers.get(i).contains("Token:") || headers.get(i).contains("Bearer Token:") ||
                    headers.get(i).contains("X-Forwarded-For:") || headers.get(i).contains("Content-Type:") ||
                    headers.get(i).contains("Referer:") || headers.get(i).contains("referer:") ||
                    headers.get(i).contains("Origin:")){
                headers.set(i,headers.get(i) + payload.replace("dns-url",(paramNumber++)+ "." +"header" +"."+dnsLog));
            }
            if(headers.get(i).contains("Accept-Language:") || headers.get(i).contains("Accept:") ||
                    headers.get(i).contains("Accept-Encoding:")){
                headers.set(i, headers.get(i) + "," + payload.replace("dns-url",(paramNumber++) + "." +"header" + "."+ dnsLog));
            }
        }
        return headers;
    }

    /**
     * URL参数的构造方法
     *
     * @param payload
     * @param dnsLogUrl
     * @return
     */
    private byte[] buildURLParameter(String payload, String dnsLogUrl) {
        byte[] newRequest;
        String dnsLog = this.getKey() + dnsLogUrl;
        newRequest = this.requestResponse().getRequest();
        int paramNumber = 1;
        // 添加header头
        List<String> headers = this.getHeaders(payload, dnsLog);
        newRequest = this.helpers.buildHttpMessage(
                headers,
                this.customBurpHelpers.getHttpRequestBody(newRequest).getBytes());

        for (int i = 0; i < this.getURLParameters().size(); i++) {
            IParameter p = this.getURLParameters().get(i);
            IParameter newParameter = null;
            switch (this.isJSONOrXML(p.getValue())){
                case 1:
                    newParameter = this.helpers.buildParameter(
                            p.getName(),
                            this.analyseJson(p.getValue(), payload, dnsLog),
                            p.getType()
                    );
                    break;
                case 2:
                    newParameter = this.helpers.buildParameter(
                            p.getName(),
                            this.analyseXML(p.getValue(), payload, dnsLog),
                            p.getType()
                    );
                    break;
                default:
                    newParameter = this.helpers.buildParameter(
                            p.getName(),
                            payload.replace("dns-url",(paramNumber++)+"."+dnsLog),
                            p.getType()
                    );
                    break;
            }

            newRequest = this.helpers.updateParameter(
                    newRequest,
                    newParameter);
        }
        return newRequest;
    }
    /**
     * 参数为a.name = a.value情况的构造方法
     *
     * @param payload
     * @param dnsLogUrl
     * @return
     */
    private byte[] buildEqualParameter(String payload, String dnsLogUrl) {

        byte[] newRequest;
        String dnsLog = this.getKey() + dnsLogUrl;
        newRequest = this.requestResponse().getRequest();
        int paramNumber = 1;
        // 添加header头
        List<String> headers = this.getHeaders(payload, dnsLog);
        newRequest = this.helpers.buildHttpMessage(
                headers,
                this.customBurpHelpers.getHttpRequestBody(newRequest).getBytes());

        for (int i = 0; i < this.getEqualParameters().size(); i++) {
            IParameter p = this.getEqualParameters().get(i);
            IParameter newParameter = null;
            switch (this.isJSONOrXML(p.getValue())){
                case 1:
                    newParameter = this.helpers.buildParameter(
                            p.getName(),
                            this.analyseJson(p.getValue(), payload, dnsLog),
                            p.getType()
                    );
                    break;
                case 2:
                    newParameter = this.helpers.buildParameter(
                            p.getName(),
                            this.analyseXML(p.getValue(), payload, dnsLog),
                            p.getType()
                    );
                    break;
                default:
                    newParameter = this.helpers.buildParameter(
                            p.getName(),
                            payload.replace("dns-url",(paramNumber++)+"."+dnsLog),
                            p.getType()
                    );
                    break;
            }

            newRequest = this.helpers.updateParameter(
                    newRequest,
                    newParameter);
        }
        return newRequest;
    }

    /**
     * body内容为file时的构造
     *
     * @param payload
     * @param dnsLogUrl
     * @return
     */
    private byte[] buildFileParameter(String payload, String dnsLogUrl) {
        byte[] newRequest;
        String dnsLog = this.getKey() + dnsLogUrl;
        newRequest = this.requestResponse().getRequest();
        int paramNumber = 1;
        // 添加header头
        List<String> headers = this.getHeaders(payload, dnsLog);
        String body = this.customBurpHelpers.getHttpRequestBody(newRequest);
        List<String> listMultipart = new ArrayList<String>();
        Pattern pattern = Pattern.compile("\n(.*?)\r\n--");
        Matcher m = pattern.matcher(body);
        while (m.find()) {
            listMultipart.add(m.group(1));
//                        stdout.println(m.group(1));
        }
        for ( String str : listMultipart) {
            body = body.replace("\n" + str + "\r\n--",
                    "\n" + payload.replace("dns-url",
                            (paramNumber++) + "." + dnsLog) + "\r\n--");
        }
        newRequest = this.helpers.buildHttpMessage(
                headers,
                body.getBytes()
        );
        return newRequest;
    }

    /**
     * body中只有json、xml的参数构造方法
     *
     * @param payload
     * @return
     */
    private byte[] buildParameter(String payload, String dnsLogUrl) {
        byte[] newRequest;
        String dnsLog = this.getKey() + dnsLogUrl;
        newRequest = this.requestResponse().getRequest();
        int paramNumber = 1;
        // 添加header头
        List<String> headers = this.getHeaders(payload, dnsLog);
        newRequest = this.helpers.buildHttpMessage(
                headers,
                this.customBurpHelpers.getHttpRequestBody(newRequest).getBytes());

        for (int i = 0; i < this.getJsonXmlFileParameters().size(); i++) {
            IParameter p = this.getJsonXmlFileParameters().get(i);
            IParameter newParameter = this.helpers.buildParameter(
                    p.getName(),
                    payload.replace("dns-url",(paramNumber++) + "."+ dnsLog),
                    p.getType()
            );

            newRequest = this.helpers.updateParameter(
                    newRequest,
                    newParameter);
        }
        return newRequest;
    }
}