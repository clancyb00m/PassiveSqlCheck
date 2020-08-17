# encoding=utf8
import re
import urllib
import xml
import random
import time
from collections import OrderedDict
from difflib import SequenceMatcher
from boolInDepthJudge import *
from parse import getUnicode
import requests
import sys
import copy
sys.dont_write_bytecode = True

# Regular expression used for detecting multipart POST data
MULTIPART_REGEX = "(?i)Content-Disposition:[^;]+;\s*name="

# Regular expression used for detecting JSON POST data
JSON_REGEX = r'(?s)\A(\s*\[)*\s*\{.*"[^"]+"\s*:\s*("[^"]*"|\d+|true|false|null).*\}\s*(\]\s*)*\Z'

# Regular expression for XML POST data
XML_REGEX = r"(?s)\A\s*<[^>]+>(.+>)?\s*\Z"

# DBMS ERROR XML
ERROR_DBMS_XML = "xml/errors.xml"

# 判断延迟的时间
TIMEOUT = 5

# 注入标记 使用#号可能有问题
SQLMARK = "@@"

# server酱的api，用于微信告警 http://sc.ftqq.com/
SERVER_JIANG_API = ''

# 结果格式 -> 注入类型、数据库类型、url、参数、payload和数据包
SQLI = '''
----------------------------------------------------------------------------------------------------
[Type]      {}
[DBMS]      {}
[URL]       {}
[Param]     {}
[Payload]   {}
----------------------------------------------------------------------------------------------------
{}
'''

class SqlChecker:
    # 原始数据包
    req = ''
    dbms = ''
    truePayload = ''
    falsePayload = ''
    # bool假的响应包
    fhtml = ''
    # bool真的响应包
    thtml = ''
    payload_dbms = ''
    # 记录当前payload类型
    ptype = ''
    # 是否有mark标记
    mark_flag = False
    # 记录超时次数
    timeout_nums = 1
    # 记录payload的值方便bool注入二次发包判断
    repayload = ''
    # 记录二次发包次数
    reSend = 1
    # 去标签的结果的二次发包次数
    noScriptReSend = 1
    true_content = ''
    # 记录SQLMARK所在位置的参数
    param = ''
    # 记录SQLMARK所在位置的参数的值
    paramvalue = ''
    level = 1
    # 记录当前测试的是第几个数据包
    rank = 1
    # 记录上一个数据包的path、host、urlparam、bodyparam，用于避免重复测试同一个数据包
    host = {}
    path = {}
    urlparam = {}
    bodyparam = {}
    # 记录相应包中的动态内容
    dynamicMarkings = []
    payload_dict = {}
    result_list = []
    # 包含SQLMARK的解析后的数据包信息，现在只有一个用途，就是为了bool发送二次请求的时候需要
    req_info = {}

    def __init__(self):
        # 非字符数字类型再这里重新声明下
        self.mark_flag = False
        self.result_list = []
        self.dynamicMarkings = []
        self.req_info = {}
        self.host = {}
        self.path = {}
        self.urlparam = {}
        self.bodyparam = {}
        # payload 有序字典，防止payload自动乱序
        self.payload_dict = OrderedDict()

    #输出结果   注入类型、数据库类型、url、参数、payload和数据包
    def out_result(self):
        for result in self.result_list:
            # 命令行输出
            print(SQLI.format(result['type'], result['dbms'], result['url'], result['param'], result['payload'], ''))
            host = re.search('://(.*?)/', self.req_info['url']).group(1)
            host = host.split(':')[0] if ':' in host else host
            # 存文件
            with open('result/%s.txt' % host, 'a') as f:
                f.write(SQLI.format(result['type'], result['dbms'], result['url'], result['param'], result['payload'], result['packet']))
                f.write("----------------------------------------------------------------------------------------------------\n\n\n")
            # 微信告警
            requests.post("https://sc.ftqq.com/%s.send" % SERVER_JIANG_API,
                            data={"text": "passiveSqlCheck", "desp": SQLI.replace('----------------------------------------------------------------------------------------------------', '').format(result['type']+'\n', result['dbms']+'\n', result['url']+'\n', result['param']+'\n', result['payload']+'\n', '')})

    # 检测报错日志报错信息
    def check_dbms_error(self):
        out_self = self
        class ErrorDbmsHandler(xml.sax.ContentHandler):
            def __init__(self):
                self.dbms = ""

            # 元素开始事件处理
            def startElement(self, tag, attr):
                self.CurrentData = tag
                if tag == "dbms":
                    dbms = attr["value"]
                    self.dbms = dbms

                if tag == "error":
                    regexp = attr["regexp"]
                    if re.search(regexp, out_self.fhtml):
                        if out_self.dbms == '':
                            out_self.dbms = self.dbms
                            out_self.result_list.append({'type': 'DBMS error', 'dbms': out_self.dbms, 'url': out_self.req_info['url'], 'param': out_self.param, 'payload': out_self.falsePayload, 'packet': out_self.req})
                            print("############################################################## DBMS error:" + out_self.dbms + " ##############################################################")

        # 创建一个 XMLReader
        parser = xml.sax.make_parser()
        # turn off namepsaces
        parser.setFeature(xml.sax.handler.feature_namespaces, 0)

        # 重写 ContextHandler
        handler = ErrorDbmsHandler()
        parser.setContentHandler(handler)

        parser.parse(ERROR_DBMS_XML)

    # 检测boolean类型注入
    def check_boolean_inject(self, positiontype):
        # self.fhtml、self.thtml还没有去除动态内容
        self.fhtml = removeDynamicContent(self.fhtml, self.dynamicMarkings)
        self.fhtml = keywordreplace(self.fhtml, self.falsePayload)

        self.thtml = removeDynamicContent(self.thtml, self.dynamicMarkings)
        self.thtml = keywordreplace(self.thtml, self.truePayload)
        fratio = compartion(self.fhtml, self.true_content)
        tratio = compartion(self.thtml, self.true_content)

        # 在自行标记注入点时，有一种情况，会导致fhtml和true_content一致而thtml和true_content有差别
        if tratio < UPPER_RATIO_BOUND and fratio > UPPER_RATIO_BOUND:
            banlance = fratio
            fratio = tratio
            tratio = banlance

        if self.reSend > 1:
            if (fratio - self.ratio) < DIFF_TOLERANCE and (tratio - self.ratio) > DIFF_TOLERANCE:
                self.result_list.append({'type': 'boolean', 'dbms': self.payload_dbms, 'url': self.req_info['url'], 'param': self.param, 'payload': self.falsePayload, 'packet': self.req})
                # self.out_result()
                self.reSend = 1
                return 1
            else:
                print(u'[-] 该payload不存在注入，程序继续执行')
                self.reSend = 1
                return 0


        # 逻辑真与原始页面相似，逻辑真与逻辑假不完全相同
        if tratio > UPPER_RATIO_BOUND and not(self.fhtml == self.thtml):
            # 如果逻辑假与原始页面相似
            if fratio > UPPER_RATIO_BOUND:
                initContent = getFilteredPageContent(self.true_content, False)
                falseContent = getFilteredPageContent(self.fhtml, str.encode(self.falsePayload))
                trueContent = getFilteredPageContent(self.thtml, str.encode(self.truePayload))

                initSet = set(initContent.split(b"\n"))
                falseSet = set(falseContent.split(b"\n"))
                trueSet = set(trueContent.split(b"\n"))

                # 如果逻辑真与原始页面一致，逻辑假与逻辑真不一致
                if initSet == trueSet != falseSet:
                    print(u'[!] 去标签')
                    if self.noScriptReSend < 2:
                        print(u'重新发包')
                        self.noScriptReSend += 1
                        if self.send_mark_sql(self.req_info, positiontype, self.repayload) == 1:
                            return 1
                    else:
                        print(u'这是去除标签后的结果，可能存在误报 SqlChecker.py # 定位：去标签比较')
                        self.result_list.append({'type': 'boolean', 'dbms': self.payload_dbms, 'url': self.req_info['url'], 'param': self.param, 'payload': self.falsePayload, 'packet': self.req})
                        # self.out_result()
                        # exit()
                        return 1
                else:
                    # 逻辑真与原始页面不一致 或者 逻辑假与逻辑真一致
                    pass
            else:
                # 如果逻辑假与原始页面不相似，则有可能存在注入，再次发包进行判断
                self.reSend += 1
                self.ratio = fratio
                print(u'[+] 可能存在注入，二次发包判断')
                if self.send_mark_sql(self.req_info, positiontype, self.repayload) == 1:
                    return 1
        else:
            # 逻辑真与原始页面不相似 或者 逻辑真与逻辑假完全相同，则进入这里
            # tratio < UPPER_RATIO_BOUND and fratio < UPPER_RATIO_BOUND
            if tratio != fratio and abs(tratio - fratio) > 0.0000001:
                self.reSend += 1
                self.ratio = fratio
                print(u'[+] 可能存在注入，二次发包判断')
                if self.send_mark_sql(self.req_info, positiontype, self.repayload) == 1:
                    return 1

    # 发送请求包，并判断注入
    def send_request(self,req_true_info,req_false_info,positiontype):
        if req_false_info['method'] == 'POST':
            if self.ptype == 'bool':
                try:
                    try:
                        # 显示参数和poc
                        if '$VALUE' in self.falsePayload:
                            print '[\033[00;34m%s\033[0m] [\033[00;32mParameter: %s\033[0m] %s' % (self.host[self.rank], self.param, self.falsePayload.replace('$VALUE',self.paramvalue))
                        else:
                            print '[\033[00;34m%s\033[0m] [\033[00;32mParameter: %s\033[0m] %s' % (self.host[self.rank], self.param, self.paramvalue + self.falsePayload)
                    except:
                        print self.param
                    frsp = requests.post(req_false_info['url'], data=req_false_info['data'], headers=req_false_info['headers'], timeout=TIMEOUT,verify=False, allow_redirects=False)
                    trsp = requests.post(req_true_info['url'], data=req_true_info['data'], headers=req_true_info['headers'], timeout=TIMEOUT,verify=False, allow_redirects=False)
                    self.fhtml = frsp.text
                    self.thtml = trsp.text
                    if self.check_boolean_inject(positiontype) == 1:
                        return 1
                    self.check_dbms_error()
                except Exception as e:
                    print e
            else:
                try:
                    try:
                        # 显示参数和poc
                        if '$VALUE' in self.falsePayload:
                            print '[\033[00;34m%s\033[0m] [\033[00;32mParameter: %s\033[0m] %s' % (self.host[self.rank], self.param, self.falsePayload.replace('$VALUE',self.paramvalue))
                        else:
                            print '[\033[00;34m%s\033[0m] [\033[00;32mParameter: %s\033[0m] %s' % (self.host[self.rank], self.param, self.paramvalue + self.falsePayload)
                    except:
                        print self.param
                    #这里allow_redirects禁止跟随是因为有些网站他会跳转到http://about:blank不是域名的地方导致异常
                    rsp = requests.post(req_true_info['url'], data=req_true_info['data'], headers=req_true_info['headers'], timeout=TIMEOUT,verify=False, allow_redirects=False)
                    self.fhtml = rsp.text
                    self.check_dbms_error()
                except requests.exceptions.Timeout:
                    self.timeout_nums += 1
                    if self.timeout_nums > 2:
                        self.timeout_nums = 1
                        #这里没有使用print(req_info[type]+'存在sql注入')是因为req_info[type]类型不确定，可能是字典或者字符串
                        self.result_list.append({'type': 'time', 'dbms': self.payload_dbms, 'url': self.req_info['url'], 'param': self.param, 'payload': self.falsePayload, 'packet': self.req})
                        # self.out_result()
                        # exit()
                        return 1
                    else:
                        if self.send_mark_sql(self.req_info, positiontype, self.repayload) == 1:
                            return 1
                except:
                    pass
        if req_false_info['method'] == 'GET':
            if self.ptype == 'bool':
                try:
                    try:
                        # 显示参数和poc
                        if '$VALUE' in self.falsePayload:
                            print '[\033[00;34m%s\033[0m] [\033[00;32mParameter: %s\033[0m] %s' % (self.host[self.rank], self.param, self.falsePayload.replace('$VALUE',self.paramvalue))
                        else:
                            print '[\033[00;34m%s\033[0m] [\033[00;32mParameter: %s\033[0m] %s' % (self.host[self.rank], self.param, self.paramvalue + self.falsePayload)
                    except:
                        print self.param
                    frsp = requests.get(req_false_info['url'].decode("unicode_escape"), data=req_false_info['data'], headers=req_false_info['headers'], timeout=TIMEOUT,verify=False, allow_redirects=False)
                    trsp = requests.get(req_true_info['url'], data=req_true_info['data'], headers=req_true_info['headers'], timeout=TIMEOUT,verify=False, allow_redirects=False)
                    self.fhtml = frsp.text
                    self.thtml = trsp.text
                    if self.check_boolean_inject(positiontype) == 1:
                        return 1
                    self.check_dbms_error()
                except Exception as e:
                    pass
            else:
                try:
                    try:
                        # 显示参数和poc
                        if '$VALUE' in self.falsePayload:
                            print '[\033[00;34m%s\033[0m] [\033[00;32mParameter: %s\033[0m] %s' % (self.host[self.rank], self.param, self.falsePayload.replace('$VALUE',self.paramvalue))
                        else:
                            print '[\033[00;34m%s\033[0m] [\033[00;32mParameter: %s\033[0m] %s' % (self.host[self.rank], self.param, self.paramvalue + self.falsePayload)
                    except:
                        print self.param
                    #这里allow_redirects禁止跟随是因为有些网站他会跳转到http://about:blank不是域名的地方导致异常
                    rsp = requests.get(req_true_info['url'], data=req_true_info['data'], headers=req_true_info['headers'], timeout=TIMEOUT,verify=False, allow_redirects=False)
                    self.fhtml = rsp.text
                    self.check_dbms_error()
                except requests.exceptions.Timeout:
                    self.timeout_nums += 1
                    if self.timeout_nums > 2:
                        self.timeout_nums = 1
                        #这里没有使用print(req_info[type]+'存在sql注入')是因为req_info[type]类型不确定，可能是字典或者字符串
                        self.result_list.append({'type': 'time', 'dbms': self.payload_dbms, 'url': self.req_info['url'], 'param': self.param, 'payload': self.falsePayload, 'packet': self.req})
                        # self.out_result()
                        # exit()
                        return 1
                    else:
                        if self.send_mark_sql(self.req_info, positiontype, self.repayload) == 1:
                            return 1
                except:
                    pass
    
    # 找到标记点前面的参数值，一方面是方便addPreSuffix使用，另一方面可以帮助判断何时修改参数值,sqlmark_site: SQLMARK的位置，比如req_info['url']
    def findParamvalue(self, sqlmark_site):
        # headers
        if isinstance(sqlmark_site, dict):
            for site in sqlmark_site:
                if SQLMARK in sqlmark_site[site]:
                    if re.search(MULTIPART_REGEX, sqlmark_site):
                        pass
                    elif re.search(JSON_REGEX, sqlmark_site):
                        pass
                    elif re.search(XML_REGEX, sqlmark_site):
                        pass
                    else:
                        self.param = site
                        self.paramvalue = sqlmark_site[site].replace(SQLMARK,'')
                        break
        # url、data、cookies
        else:
            if re.search(MULTIPART_REGEX, sqlmark_site):
                param_tuple = re.finditer(r"(?si)((Content-Disposition[^\n]+?name\s*=\s*[\"']?(?P<name>[^\"'\r\n]+)[\"']?).+?\r?\n?)(((\r)?\n)+--)", sqlmark_site)
                for param in param_tuple:
                    if SQLMARK in param.group(1):
                        self.param = param.group(3)
                        self.paramvalue = param.group(1).split('\r\n\r\n')[-1].replace(SQLMARK, '')
                        break
            elif re.search(JSON_REGEX, sqlmark_site):
                param_tuple = re.finditer(r'("(?P<name>[^"]+)"\s*:\s*".*?)"(?<!\\")', sqlmark_site)
                for param in param_tuple:
                    if SQLMARK in param.group(1):
                        self.param = param.group(2)
                        self.paramvalue = param.group(1).split('"')[-1].replace(SQLMARK,'')
                        break
            elif re.search(XML_REGEX, sqlmark_site):
                param_tuple = re.finditer(r"(<(?P<name>[^>]+)( [^<]*)?>)([^<]+)(</\2)", sqlmark_site)
                for param in param_tuple:
                    self.param = param.group(2)
                    self.paramvalue = param.group(4).replace(SQLMARK,'')
                    break
            elif '=' not in sqlmark_site:
                param_list = sqlmark_site.split('/')
                for param in param_list:
                    if SQLMARK in param:
                        self.param = 'Pseudo-static'
                        self.paramvalue = param.replace(SQLMARK, '')
                        break
            else:
                # cookie
                if ';' in sqlmark_site:
                    sqlmark_site_list = sqlmark_site.split(';')
                    for i in sqlmark_site_list:
                        if SQLMARK in i:
                            sqlmark_site = i.strip()
                            break
                self.param = re.search('(?:\?|&|)([^\?|&]*?)=(?:[^=]*?)'+SQLMARK, sqlmark_site).group(1)
                self.paramvalue = re.search('=([^=]*?)'+SQLMARK, sqlmark_site).group(1)
        # # headers
        # if isinstance(sqlmark_site, dict):
        #     for site in sqlmark_site:
        #         if SQLMARK in sqlmark_site[site]:
        #             self.param = site
        #             self.paramvalue = sqlmark_site[site].replace(SQLMARK,'')
        #             break
        # else:
        #     # cookies
        #     self.param = re.search('(?:\?|&|)(\w*?)=(?:[^=]*?)'+SQLMARK, sqlmark_site).group(1)
        #     self.paramvalue = re.search('=([^=]*?)'+SQLMARK, sqlmark_site).group(1)

    # 对注入标记进行处理，判断注入
    def check_mark_sql(self,req_info):
        # 这里兼容get和post，所以可能有些是none
        req_info['data'] = req_info['data'] if req_info['data'] != None else ""
        req_info['cookie'] = req_info['cookie'] if req_info['cookie'] != None else ""

        self.req_info = req_info

        if SQLMARK in req_info['url'] or SQLMARK in str(req_info['headers']) or SQLMARK in req_info['data'] or SQLMARK in str(req_info['cookie']):
            self.mark_flag = True
            if SQLMARK in req_info['url']:
                self.findParamvalue(req_info['url'])
                # 循环每个payload
                for ptype in self.payload_dict:
                    self.ptype = ptype
                    for dbms in self.payload_dict[ptype]:
                        self.payload_dbms = dbms
                        # ↓ 循环每个payload
                        for payload in self.payload_dict[ptype][dbms]:
                            # 替换payload，加前后缀(单引号，数字型之类的)，然后for循环遍历每个payload
                            allPayload = self.addPreSuffix(payload)
                            for payload in allPayload:
                                # 防止第一次延时，二次发包判断不延迟，但是该参数却变了，影响后续判断，所以每次更新payload，重置该值
                                self.timeout_nums = 1
                                if self.send_mark_sql(req_info, 'url', payload) == 1:
                                    return 1
            if SQLMARK in req_info['data']:
                self.findParamvalue(req_info['data'])
                for ptype in self.payload_dict:
                    self.ptype = ptype
                    for dbms in self.payload_dict[ptype]:
                        self.payload_dbms = dbms
                        for payload in self.payload_dict[ptype][dbms]:
                            # 替换payload，加前后缀，替换随机值，然后for循环遍历每个payload
                            allPayload = self.addPreSuffix(payload)
                            for payload in allPayload:
                                # 防止第一次延时，二次发包判断不延迟，但是该参数却变了，影响后续判断，所以每次更新payload，重置该值
                                self.timeout_nums = 1
                                if self.send_mark_sql(req_info, 'data', payload) == 1:
                                    return 1
            # cookie放在header类型之前，因为cookie存在注入，需要url编码，而headers都设置为解码的
            if SQLMARK in str(req_info['cookie']):
                # 找到标记点前面的值是数字型还是字符型的，方便addPreSuffix使用
                self.findParamvalue(req_info['cookie'])

                for ptype in self.payload_dict:
                    self.ptype = ptype
                    for dbms in self.payload_dict[ptype]:
                        self.payload_dbms = dbms
                        for payload in self.payload_dict[ptype][dbms]:
                            # 替换payload，加前后缀，替换随机值，然后for循环遍历每个payload
                            allPayload = self.addPreSuffix(payload)
                            for payload in allPayload:
                                # 防止第一次延时，二次发包判断不延迟，但是该参数却变了，影响后续判断，所以每次更新payload，重置该值
                                self.timeout_nums = 1
                                if self.send_mark_sql(req_info, 'cookie', payload) == 1:
                                    return 1
            if SQLMARK in str(req_info['headers']):
                # 找到标记点前面的值是数字型还是字符型的，方便addPreSuffix使用
                self.findParamvalue(req_info['headers'])

                for ptype in self.payload_dict:
                    self.ptype = ptype
                    for dbms in self.payload_dict[ptype]:
                        self.payload_dbms = dbms
                        for payload in self.payload_dict[ptype][dbms]:
                            # 替换payload，加前后缀，替换随机值，然后for循环遍历每个payload
                            allPayload = self.addPreSuffix(payload)
                            for payload in allPayload:
                                # 防止第一次延时，二次发包判断不延迟，但是该参数却变了，影响后续判断，所以每次更新payload，重置该值
                                self.timeout_nums = 1
                                if self.send_mark_sql(req_info, 'headers', payload) == 1:
                                    return 1

    def send_mark_sql(self, req_info, positiontype, payload):
        # 记录这个payload，为了二次发包判断的时候使用
        self.repayload = payload
        # 替换随机值
        truePayload, falsePayload = self.getRandomPayload(payload)
        # 深拷贝
        req_true_info = copy.deepcopy(req_info)
        req_false_info = copy.deepcopy(req_info)
        self.falsePayload = falsePayload
        self.truePayload = truePayload

        if positiontype == 'url' or positiontype == 'data':
            if '$VALUE' in payload or '1-CASE' in payload:
                req_true_info[positiontype] = req_info[positiontype].replace(self.paramvalue+SQLMARK, truePayload.replace('$VALUE', self.paramvalue))
                req_false_info[positiontype] = req_info[positiontype].replace(self.paramvalue+SQLMARK, falsePayload.replace('$VALUE', self.paramvalue))
            else:
                req_true_info[positiontype] = req_info[positiontype].replace(SQLMARK, truePayload)
                req_false_info[positiontype] = req_info[positiontype].replace(SQLMARK, falsePayload)
            if 'OR' in payload:
                req_true_info[positiontype] = req_info[positiontype].replace(self.paramvalue+SQLMARK, '-9834' + truePayload)
                req_false_info[positiontype] = req_info[positiontype].replace(self.paramvalue+SQLMARK, '-9834' + falsePayload)
            if self.send_request(req_true_info, req_false_info, positiontype) == 1:
                return 1
        elif positiontype == 'cookie':
            if '$VALUE' in payload or '1-CASE' in payload:
                req_true_info['headers']['Cookie'] = req_info['headers']['Cookie'].replace(self.paramvalue+SQLMARK, truePayload.replace('$VALUE', self.paramvalue))
                req_false_info['headers']['Cookie'] = req_info['headers']['Cookie'].replace(self.paramvalue+SQLMARK, falsePayload.replace('$VALUE', self.paramvalue))
            else:
                req_true_info['headers']['Cookie'] = req_info['headers']['Cookie'].replace(SQLMARK, truePayload)
                req_false_info['headers']['Cookie'] = req_info['headers']['Cookie'].replace(SQLMARK, falsePayload)
            if 'OR' in payload:
                req_true_info['headers']['Cookie'] = req_info['headers']['Cookie'].replace(self.paramvalue+SQLMARK, '-9834' + truePayload)
                req_false_info['headers']['Cookie'] = req_info['headers']['Cookie'].replace(self.paramvalue+SQLMARK, '-9834' + falsePayload)
            if self.send_request(req_true_info, req_false_info, 'headers') == 1:
                return 1
        elif positiontype == 'headers':
            # header头是不会url解码的，所以对于headers进行解码
            truePayload = urllib.unquote(truePayload)
            falsePayload = urllib.unquote(falsePayload)

            req_true_info['headers'] = {}
            req_false_info['headers'] = {}

            for header in req_info['headers']:
                if '$VALUE' in payload or '1-CASE' in payload:
                    req_true_info['headers'][header] = req_info['headers'][header].replace(self.paramvalue+SQLMARK, truePayload.replace('$VALUE', self.paramvalue))
                    req_false_info['headers'][header] = req_info['headers'][header].replace(self.paramvalue+SQLMARK, falsePayload.replace('$VALUE', self.paramvalue))
                else:
                    req_true_info['headers'][header] = req_info['headers'][header].replace(SQLMARK, truePayload)
                    req_false_info['headers'][header] = req_info['headers'][header].replace(SQLMARK, falsePayload)
                if 'OR' in payload:
                    req_true_info['headers'][header] = req_info['headers'][header].replace(self.paramvalue+SQLMARK, '-9834' + truePayload)
                    req_false_info['headers'][header] = req_info['headers'][header].replace(self.paramvalue+SQLMARK, '-9834' + falsePayload)

            if self.send_request(req_true_info, req_false_info, 'headers') == 1:
                return 1

    # 加前后缀
    def addPreSuffix(self, payload):
        fullpayload = []

        if self.level == 1:
            prefix = [
                "'",
                '',
            ]
        else:
            prefix = [
                "'", '', '"',
                "')", ')', '")',
                "'))", '))', '"))'
            ]

        # 判断当前参数值是否是字符串，如果是字符串，则不用数字型进行注入
        isStr = 0
        try:
            if self.paramvalue != '':
                float(self.paramvalue)
        except ValueError:
            isStr = 1

        for pre in prefix:
            if pre == "'":
                suffix = " AND '$A'='$A"
                payload1 = payload.replace('$FH', "'")
                payload1 = payload1.replace('$QFH', "'")
                payload1 = payload1.replace('$HFH', "'")
            elif pre == '':
                if isStr == 1:
                    continue
                suffix = " AND $RR=$RR"
                payload1 = payload.replace('$FH', "")
                payload1 = payload1.replace('$QFH', "")
                payload1 = payload1.replace('$HFH', "")
            elif pre == '"':
                suffix = ' AND "$A"="$A'
                payload1 = payload.replace('$FH', '"')
                payload1 = payload1.replace('$QFH', '"')
                payload1 = payload1.replace('$HFH', '"')
            elif pre == "')":
                suffix = " AND ('$A'='$A"
                payload1 = payload.replace('$FH', "'")
                payload1 = payload1.replace('$QFH', "('")
                payload1 = payload1.replace('$HFH', "')")
            elif pre == ')':
                if isStr == 1:
                    continue
                suffix = " AND ($RR=$RR"
                payload1 = payload.replace('$FH', "")
                payload1 = payload1.replace('$QFH', "(")
                payload1 = payload1.replace('$HFH', ")")
            elif pre == '")':
                suffix = ' AND ("$A"="$A'
                payload1 = payload.replace('$FH', '"')
                payload1 = payload1.replace('$QFH', '("')
                payload1 = payload1.replace('$HFH', '")')
            elif pre == "'))":
                suffix = " AND (('$A'='$A"
                payload1 = payload.replace('$FH', "'")
                payload1 = payload1.replace('$QFH', "(('")
                payload1 = payload1.replace('$HFH', "'))")
            elif pre == '))':
                if isStr == 1:
                    continue
                suffix = " AND (($RR=$RR"
                payload1 = payload.replace('$FH', "")
                payload1 = payload1.replace('$QFH', "((")
                payload1 = payload1.replace('$HFH', "))")
            elif pre == '"))':
                suffix = ' AND (("$A"="$A'
                payload1 = payload.replace('$FH', '"')
                payload1 = payload1.replace('$QFH', '(("')
                payload1 = payload1.replace('$HFH', '"))')

            if 'LIKE_' in payload1 or 'LIKE(_' in payload1 or 'LIKE((_' in payload1:
                continue
            elif '$R1LIKE$R2' in payload1:
                payload1 = payload1.replace('AND', 'AND ')
                payload1 = payload1.replace('OR', 'OR ')
                payload1 = payload1.replace('LIKE', ' LIKE ')
            elif ' $S ' in payload1:
                payload1 = payload1.replace(' $S ',' $R2 ')
            elif 'THEN1ELSE' in payload1:
                payload1 = payload1.replace('THEN1ELSE','THEN 1 ELSE')

            # 如果存在LIKE则替换等于号为LIKE
            if 'LIKE' in payload and 'RLIKE' not in payload:
                if '$RR' in suffix:
                    suffix = suffix.replace('=', ' LIKE ')
                else:
                    suffix = suffix.replace('=', 'LIKE')

            # 需要后缀的就添加后缀
            if '$HZ' in payload:
                payload1 = payload1.replace('$HZ', suffix)
            
            # 替换空格
            if ' ' in payload1:
                if '-case' in payload1 or '||$R' in payload1 or ';WAITFOR' in payload1 or ',(' in payload1:
                    fullpayload.append('{}{}'.format(pre, payload1))
                else:
                    fullpayload.append('{} {}'.format(pre, payload1))
            else:
                fullpayload.append('{}{}'.format(pre, payload1))
        return fullpayload
    
    # 替换随机值，分正反包
    def getRandomPayload(self, payload):
        '''
            $RR 数字
            $R1、$R2、$R3、$R4
            $FR -> firstR,$RR的第一个数字，比如：'2019' -> '2'
            $FOUR -> 
            $S -> 字符串[a-zA-Z]
            $A -> 数字字母随机
        '''

        strs = 'aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ0123456789'
        
        ranInt1 = random.randint(1000,3333)
        ranInt2 = random.randint(3334,5555)
        if '$RR' in payload:
            ranInt = random.randint(1000,9999)
            payload = payload.replace('$RR',str(ranInt))
        if '$FR' in payload:
            payload = payload.replace('$FR',str(ranInt1)[:1])
        if '$R3' in payload:
            ranInt3 = random.randint(5556,7777)
            payload = payload.replace('$R3',str(ranInt3))
        if '$R4' in payload:
            ranInt4 = random.randint(7778,9999)
            payload = payload.replace('$R4',str(ranInt4))
        if '$S' in payload:
            ranStr = strs[random.randint(0,51)] + strs[random.randint(0,51)] + strs[random.randint(0,51)] + strs[random.randint(0,51)]
            payload = payload.replace('$S',ranStr)
        if '$A' in payload:
            ranAny = strs[random.randint(0,61)] + strs[random.randint(0,61)] + strs[random.randint(0,61)] + strs[random.randint(0,61)]
            payload = payload.replace('$A', ranAny)
        if '$R1' in payload and '$R2' in payload:
            if 'DECODE(INSTR' in payload or '||$R1/$R2||' in payload:
                tpayload = payload
                fpayload = payload.replace('$R2','0')
            else:
                tpayload = payload.replace('$R2','$R1')
                fpayload = payload
        else:
            tpayload = payload
            fpayload = payload
        if '$XHX' in payload:
            tpayload = payload.replace('$XHX','')
            fpayload = payload.replace('$XHX','____')
        
        tpayload = tpayload.replace('$R1',str(ranInt1))
        tpayload = tpayload.replace('$R2',str(ranInt2))
        fpayload = fpayload.replace('$R1',str(ranInt1))
        fpayload = fpayload.replace('$R2',str(ranInt2))

        return tpayload, fpayload