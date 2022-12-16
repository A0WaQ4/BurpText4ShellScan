package burp;

import burp.Application.RemoteCmdExtension.RemoteCmd;
import burp.Bootstrap.*;
import burp.CustomErrorException.TaskTimeoutException;
import burp.DnsLogModule.DnsLog;
import burp.UI.*;

import java.io.PrintWriter;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class BurpExtender implements IBurpExtender, IScannerCheck, IExtensionStateListener {
    public static String NAME="Text4ShellScan";
    public Tags tags;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private GlobalVariableReader globalVariableReader;

    private PrintWriter stdout;
    private PrintWriter stderr;

    private YamlReader yamlReader;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);

        // 全局变量的数据保存地址
        // 用于在程序执行的过程中能够实时的修改变量数据使用
        this.globalVariableReader = new GlobalVariableReader();

        // 是否卸载扩展
        // 用于卸载插件以后,把程序快速退出去,避免卡顿
        // true = 已被卸载, false = 未卸载
        this.globalVariableReader.putBooleanData("isExtensionUnload", false);

        this.tags = new Tags(callbacks, NAME);

        callbacks.setExtensionName(NAME);
        callbacks.registerScannerCheck(this);
        callbacks.registerExtensionStateListener(this);

        // 配置文件
        this.yamlReader = YamlReader.getInstance(callbacks);
        // 基本信息输出
        this.stdout.println(basicInformationOutput());
    }
    /**
     * 基本信息输出
     * @return
     */
    private static String basicInformationOutput() {
        String str1 = "===================================\n";
        String str2 = String.format("LOADING %s SUCCESS\n", NAME);
        String str3 = String.format("GitHub:https://github.com/A0WaQ4/BurpText4ShellScan\n");
        String str4 = String.format("Author:A0WaQ4\n");
        String str5 = "===================================\n";
        String detail = str1 + str2 + str3 + str4 + str5;
        return detail;
    }
    @Override
    public void extensionUnloaded() {

    }

    /**
     * 进行被动扫描
     * @param baseRequestResponse 基础的请求返回包
     * @return null
     */
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        List<IScanIssue> issues = new ArrayList<>();

        List<String> domainNameBlacklist = this.yamlReader.getStringList("scan.domainName.blacklist");
        // 基础请求分析
        BurpAnalyzedRequest baseAnalyzedRequest = new BurpAnalyzedRequest(this.callbacks, this.tags, baseRequestResponse);

        CustomBurpUrl baseBurpUrl = new CustomBurpUrl(this.callbacks, baseRequestResponse);
        CustomBurpParameters baseBurpParameters = new CustomBurpParameters(this.callbacks,baseRequestResponse);


        // 判断域名黑名单
        if (domainNameBlacklist != null && domainNameBlacklist.size() >= 1) {
            if (isMatchDomainName(baseBurpUrl.getRequestHost(), domainNameBlacklist)) {
                return null;
            }
        }

        // 判断当前请求后缀,是否为url黑名单后缀
        if (this.isUrlBlackListSuffix(baseBurpUrl)) {
            return null;
        }

        try {
            // 远程cmd扩展
            IScanIssue remoteCmdIssuesDetail = this.remoteCmdExtension(baseAnalyzedRequest);
            if (remoteCmdIssuesDetail != null) {
                issues.add(remoteCmdIssuesDetail);
                return issues;
            }
        } catch (TaskTimeoutException e) {
            this.stdout.println("========插件错误-超时错误============");
            this.stdout.println(String.format("url: %s", baseBurpUrl.getHttpRequestUrl().toString()));
            this.stdout.println("请使用该url重新访问,若是还多次出现此错误,则很有可能waf拦截");
            this.stdout.println("错误详情请查看Extender里面对应插件的Errors标签页");
            this.stdout.println("========================================");
            this.stdout.println(" ");
            e.printStackTrace(this.stderr);
        } catch (Exception e) {
            this.stdout.println("========插件错误-未知错误============");
            this.stdout.println(String.format("url: %s", baseBurpUrl.getHttpRequestUrl().toString()));
            this.stdout.println("请使用该url重新访问,若是还多次出现此错误,则很有可能waf拦截");
            this.stdout.println("错误详情请查看Extender里面对应插件的Errors标签页");
            this.stdout.println("========================================");
            this.stdout.println(" ");
            e.printStackTrace(this.stderr);
        } finally {
            this.stdout.println("================扫描完毕================");
            this.stdout.println(String.format("url: %s", baseBurpUrl.getHttpRequestUrl().toString()));
            this.stdout.println("========================================");
            this.stdout.println(" ");

            return issues;
        }



    }

    /**
     * 远程cmd扩展
     *
     * @param analyzedRequest
     * @return IScanIssue issues
     * @throws ClassNotFoundException
     * @throws NoSuchMethodException
     * @throws InvocationTargetException
     * @throws InstantiationException
     * @throws IllegalAccessException
     */
    private IScanIssue remoteCmdExtension(BurpAnalyzedRequest analyzedRequest) throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException, InstantiationException, IllegalAccessException {
        String provider = this.yamlReader.getString("application.remoteCmdExtension.config.provider");

        DnsLog dnsLog = new DnsLog(this.callbacks, this.yamlReader.getString("dnsLogModule.provider"));
        RemoteCmd remoteCmd = new RemoteCmd(this.globalVariableReader, this.callbacks, analyzedRequest, dnsLog, this.yamlReader, provider);
        if (!remoteCmd.run().isIssue()) {
            return null;
        }

        IHttpRequestResponse httpRequestResponse = remoteCmd.run().getHttpRequestResponse();

        int tagId = this.tags.add(
                remoteCmd.run().getExtensionName(),
                this.helpers.analyzeRequest(httpRequestResponse).getMethod(),
                new CustomBurpUrl(this.callbacks, httpRequestResponse).getHttpRequestUrl().toString(),
                this.helpers.analyzeResponse(httpRequestResponse.getResponse()).getStatusCode() + "",
                "[+] found Text4Shell command execution",
                String.valueOf(httpRequestResponse.getResponse().length),
                remoteCmd.run().getHttpRequestResponse()
        );

        remoteCmd.run().consoleExport();
        return remoteCmd.run().export();
    }

    /**
     * 判断是否查找的到指定的域名
     *
     * @param domainName     需匹配的域名
     * @param domainNameList 待匹配的域名列表
     * @return 是=true 否=false
     */
    private static Boolean isMatchDomainName(String domainName, List<String> domainNameList) {
        domainName = domainName.trim();

        if (domainName.length() <= 0) {
            return false;
        }

        if (domainNameList == null || domainNameList.size() <= 0) {
            return false;
        }

        if (domainName.contains(":")) {
            domainName = domainName.substring(0, domainName.indexOf(":"));
        }

        String reverseDomainName = new StringBuffer(domainName).reverse().toString();

        for (String domainName2 : domainNameList) {
            domainName2 = domainName2.trim();

            if (domainName2.length() <= 0) {
                continue;
            }

            if (domainName2.contains(":")) {
                domainName2 = domainName2.substring(0, domainName2.indexOf(":"));
            }

            String reverseDomainName2 = new StringBuffer(domainName2).reverse().toString();

            if (domainName.equals(domainName2)) {
                return true;
            }

            if (reverseDomainName.contains(".") && reverseDomainName2.contains(".")) {
                List<String> splitDomainName = new ArrayList<String>(Arrays.asList(reverseDomainName.split("[.]")));

                List<String> splitDomainName2 = new ArrayList<String>(Arrays.asList(reverseDomainName2.split("[.]")));

                if (splitDomainName.size() <= 0 || splitDomainName2.size() <= 0) {
                    continue;
                }

                if (splitDomainName.size() < splitDomainName2.size()) {
                    for (int i = splitDomainName.size(); i < splitDomainName2.size(); i++) {
                        splitDomainName.add("*");
                    }
                }

                if (splitDomainName.size() > splitDomainName2.size()) {
                    for (int i = splitDomainName2.size(); i < splitDomainName.size(); i++) {
                        splitDomainName2.add("*");
                    }
                }

                int ii = 0;
                for (int i = 0; i < splitDomainName.size(); i++) {
                    if (splitDomainName2.get(i).equals("*")) {
                        ii = ii + 1;
                    } else if (splitDomainName.get(i).equals(splitDomainName2.get(i))) {
                        ii = ii + 1;
                    }
                }

                if (ii == splitDomainName.size()) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * 判断是否url黑名单后缀
     * 大小写不区分
     *
     * @param burpUrl 目标url
     * @return 是 = true, 否 = false
     */
    private boolean isUrlBlackListSuffix(CustomBurpUrl burpUrl) {
        if (!this.yamlReader.getBoolean("urlBlackListSuffix.config.isStart")) {
            return false;
        }

        String noParameterUrl = burpUrl.getHttpRequestUrl().toString().split("\\?")[0];
        String urlSuffix = noParameterUrl.substring(noParameterUrl.lastIndexOf(".") + 1);

        List<String> suffixList = this.yamlReader.getStringList("urlBlackListSuffix.suffixList");
        if (suffixList == null || suffixList.size() == 0) {
            return false;
        }

        for (String s : suffixList) {
            if (s.toLowerCase().equals(urlSuffix.toLowerCase())) {
                return true;
            }
        }

        return false;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse iHttpRequestResponse, IScannerInsertionPoint iScannerInsertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue iScanIssue, IScanIssue iScanIssue1) {
        return 0;
    }
}