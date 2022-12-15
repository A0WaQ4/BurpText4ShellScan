package burp.Bootstrap;

import java.util.List;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import burp.*;
import burp.UI.Tags;
import com.alibaba.fastjson.JSON;
import org.checkerframework.checker.units.qual.C;
import org.dom4j.Document;
import org.dom4j.DocumentHelper;

public class BurpAnalyzedRequest {
    private IBurpExtenderCallbacks callbacks;

    private IExtensionHelpers helpers;

    private CustomBurpUrl customBurpUrl;

    private CustomBurpHelpers customBurpHelpers;

    private List<IParameter> equalParameters = new ArrayList<>();
    private List<IParameter> JsonXmlFileParameters = new ArrayList<>();
    private IParameter iParameter;

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
//        initEligibleJsonParameters();
    }

    public IHttpRequestResponse requestResponse() {
        return this.requestResponse;
    }

    public IRequestInfo analyzeRequest() {
        return this.helpers.analyzeRequest(this.requestResponse.getRequest());
    }

    /**
     * 初始化非json、xml、xml_attr参数
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

    private void initJsonXmlFileParameters() {
        if (analyzeRequest().getParameters().isEmpty()) {
            return;
        }

        for (IParameter p : analyzeRequest().getParameters()) {
            // 类型为cookie、xml_attr不加入
            if (p.getType() == 2 || p.getType() == 4) {
                continue;
            }
            if (p.getName() == null || "".equals(p.getName())) {
                continue;
            }
            this.JsonXmlFileParameters.add(p);
        }
    }



    /**
     * 解析json字符串，普通和嵌套类型都可
     *
     * @param jsonData 请求包的json数据
     * @param payload  crlf的payload
     * @return 返回添加payload的json字符串
     */
    public String  analyseJson(String jsonData , String payload) {
        String jsonResult = "";
        boolean j = false;
        for(int i=0;i<jsonData.length();i++){
            if(j&&jsonData.charAt(i) == '"'){
                j = false;
                continue;
            }
            if(j){
                continue;
            }
            if(jsonData.charAt(i) == '"'&&jsonData.charAt(i-1) == ':'){
                jsonResult = jsonResult + "\"" + payload + "\"";
                j = true;
            }else{
                jsonResult = jsonResult + jsonData.charAt(i);
            }

        }
        return jsonResult;
    }

    /**
     * 获取所有的json参数
     *
     * @return List<IParameter>
     */
    public List<IParameter> getEqualParameters() {
        return this.equalParameters;
    }


    /**
     * 获取所有符合条件的json参数
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

        List<String> headers = this.analyzeRequest().getHeaders();
        byte[] request = this.requestResponse.getRequest();
        if(this.customBurpHelpers.getHttpRequestBody(request) != null){
            switch (this.analyzeRequest().getContentType()){
                case 1:
                case 2:
                case 3:
                case 4:
            }
        }
//        if (newHeaders != null && newHeaders.size() != 0) {
//            headers.addAll(newHeaders);
//        }
        if(this.customBurpUrl.getRequestQuery() != null && this.customBurpHelpers.getHttpRequestBody(request) != null){
            newRequest = this.buildParameter(payload,  headers, dnsLogUrl);
        } else {
            switch (this.analyzeRequest().getContentType()){
                case 0:
                case 1:
                case 2:
                default:
                    newRequest = this.buildParameter(payload, headers, dnsLogUrl);
            }
        }

//        if (this.analyzeRequest().getContentType() == 4) {
//            // POST请求包提交的数据为json时的处理
//            newRequest = this.buildParameter(payload, this.buildHttpMessage(payload), headers);
//        } else {
//            // 普通数据格式的处理
//            newRequest = this.buildParameter(payload, null, headers);
//        }

        IHttpRequestResponse newHttpRequestResponse = this.callbacks.makeHttpRequest(this.requestResponse().getHttpService(), newRequest);
        return newHttpRequestResponse;
    }



    /**
     * 判断字符串为JSON格式还是XML格式
     *
     * @param str 参数的value或者POST包的body
     * @return 返回"JSON"、"XML"和null
     */
    public String isJSONOrXMLUpload(String str){
        try {
            JSON.parse(str.replaceAll("(\\[(.*?)])","\"test\""));
            return "JSON";
        } catch (Exception e) {
        }

        try {
            DocumentHelper.parseText(str);
            return "XML";
        } catch (Exception e) {
        }

        return null;
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
     * json、xml的参数构造方法
     *
     * @param payload
     * @return
     */
    private byte[] buildParameter(String payload, List<String> headers, String dnsLogUrl) {
        byte[] newRequest;
        String dnsLog = this.helpers.analyzeRequest(this.requestResponse).getMethod() + "."
                + this.customBurpUrl.getRequestHost() + "."
                + this.customBurpUrl.getRequestPath().replace("/",".") + dnsLogUrl;
        newRequest = this.requestResponse().getRequest();
        int paramNumber = 0;
        // 添加header头
        for(int i =1; i<headers.size();i++){
            if(headers.get(i).contains("User-Agent:") || headers.get(i).contains("token:") ||
                    headers.get(i).contains("Token:") || headers.get(i).contains("Bearer Token:") ||
                    headers.get(i).contains("X-Forwarded-For:") || headers.get(i).contains("Content-Type:") ||
                    headers.get(i).contains("Referer:") || headers.get(i).contains("referer:") ||
                    headers.get(i).contains("Origin:")){
                headers.set(i,headers.get(i) + payload.replace("dns-url",(paramNumber++)+"."+dnsLog));
            }
            if(headers.get(i).contains("Accept-Language:") || headers.get(i).contains("Accept:") ||
                    headers.get(i).contains("Accept-Encoding:")){
                headers.set(i, headers.get(i) + "," + payload.replace("dns-url",(paramNumber++)+"."+dnsLog));
            }
        }
        newRequest = this.helpers.buildHttpMessage(
                headers,
                this.customBurpHelpers.getHttpRequestBody(newRequest).getBytes());

        for (int i = 0; i < this.getJsonXmlFileParameters().size(); i++) {
            IParameter p = this.getJsonXmlFileParameters().get(i);
            IParameter newParameter = this.helpers.buildParameter(
                    p.getName(),
                    payload.replace("dnslog-url",(paramNumber++)+"."+dnsLog),
                    p.getType()
            );

            newRequest = this.helpers.updateParameter(
                    newRequest,
                    newParameter);
        }
        return newRequest;
    }
}