# encoding=utf8

"""
定义了一些基本函数
"""

import urlparse
import urllib
import xml.sax
from xml.dom.minidom import parse
import xml.dom.minidom
import re
from conf.setting import *
from boolInDepthJudge import *
import requests
from difflib import *
import sys
import base64

sys.dont_write_bytecode = True
#设置utf8编码
reload(sys)
sys.setdefaultencoding('utf8')

# 从xml中读取请求包到字典当中
def read_xml_reqs(filename):
    reqs = []
    DOMTree = xml.dom.minidom.parse(filename)
    collection = DOMTree.documentElement

    item_collection = collection.getElementsByTagName("item")
    for item in item_collection:
        request = item.getElementsByTagName("request")
        req = request[0].firstChild.data
        reqs.append(base64.b64decode(req))
    return reqs

# 从xml中读取payload到字典当中
# 格式：{'bool':}
def read_xml_payloads():
    global g_sql_info
    DOMTree = xml.dom.minidom.parse(PAYLOADS_XML)
    collection = DOMTree.documentElement

    type_collection = collection.getElementsByTagName("type")
    for type_node in type_collection:
        ptype = str(type_node.getAttribute("value"))
        g_sql_info.payload_dict[ptype] = {}
        dbms_collection = type_node.getElementsByTagName("dbms")
        for dbms_node in dbms_collection:
            dbms = str(dbms_node.getAttribute("value"))
            g_sql_info.payload_dict[ptype][dbms] = []
            payloads = dbms_node.getElementsByTagName('payload')
            for payload in payloads:
                payload = payload.getAttribute("value")
                g_sql_info.payload_dict[ptype][dbms].append(payload)


# 解析data参数
def parse_data(data):

    # #解析data,id=1&name=lufei&password=123456
    # param_list = urlparse.parse_qsl(data, keep_blank_values=True)

    # #parse_qsl函数会自动unquote,导致一些url %BE%AD%B7%BD变成字符串，搞乱了原来的编码，所以这里需要quote复原一下
    # quote_param_list = []
    # for parm in param_list:
    #     quote_param_list.append(((urllib.unquote(parm[0])),(urllib.unquote(parm[1]))))
    # 上面的逻辑解决不掉中文字符的问题，重写如下：
    quote_param_list = []
    if not data:
        return quote_param_list
    if '&' in data:
        per_data = data.split('&')
        for pdata in per_data:
            try:
                quote_param_list.append(((pdata.split('=')[0]),(pdata.split('=')[1])))
            except:
                quote_param_list.append((pdata, ''))
    else:
        quote_param_list.append(((data.split('=')[0]),(data.split('=')[1])))

    return quote_param_list

# 解析json
def parse_json(poc_param_list,param_index,param_name,para_json_value,payload):
    json_param_tuple = re.finditer(r'("(?P<name>[^"]+)"\s*:\s*".*?)"(?<!\\")', para_json_value)
    for json_param in json_param_tuple:
        poc_json_param = para_json_value[:json_param.regs[1][0]] + json_param.group(1) + payload + para_json_value[json_param.regs[1][1]:]
        # payload构造
        if param_index == 0:
            poc_param_list = [(param_name, poc_json_param)] + poc_param_list[param_index + 1:]
        else:
            poc_param_list = poc_param_list[0:param_index] + [(param_name, poc_json_param)] + poc_param_list[param_index + 1:]

        def link(param):
            return param[0] + '=' + param[1]

        data = '&'.join(map(link, poc_param_list))
        return data


# 检测https
def check_https(req_info):
    for header in req_info['headers']:
        if header.upper() == 'Origin'.upper() or header.upper() == 'Referer'.upper():
            if req_info['host'] in req_info['headers'][header]:
                if 'https' in req_info['headers'][header]:
                    return True
    try:
        req_right_info = req_info.copy()
        if req_right_info['method'] == 'POST':
            # req_right_info = req_info.copy()
            req_right_info['url'] = req_right_info['url'].replace(SQLMARK,"")
            req_right_info['data'] = req_right_info['data'].replace(SQLMARK, "")
            #req_right_info['headers'] = {}
            for header in req_right_info['headers']:
                req_right_info['headers'][header] = (req_right_info['headers'][header]).replace(SQLMARK, "")
            try:
                rsp = requests.post(req_right_info['url'], data=req_right_info['data'], headers=req_right_info['headers'], timeout=TIMEOUT,verify=True, allow_redirects=False)
                if str(rsp.status_code)[0] == '3' and rsp.headers['Location'] and 'https://'+req_right_info['host'] in rsp.headers['Location']:
                    return True
            except requests.exceptions.SSLError,err:
                print(err)
                return True
            except requests.exceptions.ConnectionError,err:
                print(err)
                return True
        if req_right_info['method'] == 'GET':
            # req_right_info = req_info.copy()
            req_right_info['url'] = req_right_info['url'].replace(SQLMARK,"")
            #req_right_info['headers'] = {}
            try:
                rsp = requests.get(req_right_info['url'], headers=req_right_info['headers'], timeout=TIMEOUT, verify=True,allow_redirects=False)
                if str(rsp.status_code)[0] == '3' and rsp.headers['Location'] and 'https://'+req_right_info['host'] in rsp.headers['Location']:
                    return True
            except requests.exceptions.SSLError,err:
                print(err)
                return True
            except requests.exceptions.ConnectionError,err:
                print(err)
                return True
    except:
        pass

def get_right_resp(req_info):
    global g_sql_info
    if req_info['method'] == 'POST':
        try:
            req_right_info = req_info.copy()
            req_right_info['url'] = req_right_info['url'].replace(SQLMARK,"")
            req_right_info['data'] = req_right_info['data'].replace(SQLMARK, "")
            req_right_info['headers'] = {}
            for header in req_info['headers']:
                req_right_info['headers'][header] = (req_info['headers'][header]).replace(SQLMARK, "")

            # 发送两次请求包，判断是否存在动态内容，如果存在，则标记出来
            rsp1 = requests.post(req_right_info['url'], data=req_right_info['data'], headers=req_right_info['headers'], timeout=TIMEOUT,verify=False, allow_redirects=False)
            rsp2 = requests.post(req_right_info['url'], data=req_right_info['data'], headers=req_right_info['headers'], timeout=TIMEOUT,verify=False, allow_redirects=False)

            ratio = compartion(rsp1.text,rsp2.text)
            if ratio < UPPER_RATIO_BOUND:
                # 存在动态内容,如时间戳等影响ratio值的因素
                g_sql_info.dynamicMarkings = findDynamicContent(rsp1.text,rsp2.text)
                g_sql_info.true_content = removeDynamicContent(rsp1.text, g_sql_info.dynamicMarkings)
            else:
                # 不存在动态内容
                g_sql_info.true_content = rsp1.text
        except Exception, err:
            print(err)
    if req_info['method'] == 'GET':
        try:
            req_right_info = req_info.copy()
            req_right_info['url'] = req_right_info['url'].replace(SQLMARK,"")
            req_right_info['headers'] = {}
            for header in req_info['headers']:
                req_right_info['headers'][header] = (req_info['headers'][header]).replace(SQLMARK, "")
            
            # 发送两次请求包，判断是否存在动态内容，如果存在，则标记出来
            rsp1 = requests.get(req_right_info['url'], headers=req_right_info['headers'], timeout=TIMEOUT, verify=False,allow_redirects=False)
            rsp2 = requests.get(req_right_info['url'], headers=req_right_info['headers'], timeout=TIMEOUT, verify=False,allow_redirects=False)
            
            ratio = compartion(rsp1.text,rsp2.text)
            if ratio < UPPER_RATIO_BOUND:
                # 存在动态内容,如时间戳等影响ratio值的因素
                g_sql_info.dynamicMarkings = findDynamicContent(rsp1.text,rsp2.text)
                g_sql_info.true_content = removeDynamicContent(rsp1.text, g_sql_info.dynamicMarkings)
            else:
                # 不存在动态内容
                g_sql_info.true_content = rsp1.text
        except Exception,err:
            print(err)
