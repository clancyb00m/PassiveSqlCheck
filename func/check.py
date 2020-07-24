# encoding=utf8
import sys
import json
from parse import *
from common import *
from colorlog import ColoredFormatter

sys.dont_write_bytecode = True

def check(req):
    requests.packages.urllib3.disable_warnings()

    g_sql_info.req = req
    g_sql_info.level = args.level

    # 解析数据包
    req_info = parseRequestFile(req)
    # 判断是否该数据包已测试过
    if g_sql_info.host == {} and g_sql_info.path == {} and g_sql_info.urlparam == {} and g_sql_info.bodyparam == {}:
        g_sql_info.host[g_sql_info.rank] = req_info['host']
        g_sql_info.path[g_sql_info.rank] = req_info['path']
        g_sql_info.urlparam[g_sql_info.rank] = req_info['urlparam']
        g_sql_info.bodyparam[g_sql_info.rank] = req_info['bodyparam']
    else:
        tested = 0
        for i in g_sql_info.host:
            if req_info['host'] == g_sql_info.host[i] and req_info['path'] == g_sql_info.path[i] and req_info['urlparam'] == g_sql_info.urlparam[i] and req_info['bodyparam'] == g_sql_info.bodyparam[i]:
                tested = 1
        if tested == 1:
            # 该数据包已测试过，直接进行下一个
            return 0
        else:
            # 该数据包未测试过
            g_sql_info.host[g_sql_info.rank] = req_info['host']
            g_sql_info.path[g_sql_info.rank] = req_info['path']
            g_sql_info.urlparam[g_sql_info.rank] = req_info['urlparam']
            g_sql_info.bodyparam[g_sql_info.rank] = req_info['bodyparam']

    #添加user-agent，因为waf真的从这个判断恶意请求
    if not req_info['headers'].has_key("User-Agent"):
        req_info['headers']['User-Agent'] = 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.21 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.21'

    req_headers = json.dumps(req_info['headers'])
    if check_https(req_info) == True:
        parse_url = urlparse.urlparse(req_info['url'])
        req_info['url'] = "%s://%s:%s%s%s" % ("https", parse_url.hostname, "443", parse_url.path, "?" + parse_url.query if parse_url.query else "")
    req_info['headers'] = json.loads(req_headers)
    try:
        print(req_info['url'])
    except:
        pass

    #获取正确页面
    get_right_resp(req_info)

    # 加载payload 到 g_sql_info.payload_dict
    read_xml_payloads()

    #检测原始的mark标记注入
    if req_info['data'] and urllib.quote(SQLMARK) in req_info['data']:
        req_info['data'] = req_info['data'].replace(urllib.quote(SQLMARK), SQLMARK)
    if g_sql_info.check_mark_sql(req_info) == 1:
        return 1

    #有标记的注入不进入下面的检查
    if g_sql_info.mark_flag == True:
        return 1

    # multipart
    if re.search(MULTIPART_REGEX, req_info['data']):
        param_tuple = re.finditer(r"(?si)((Content-Disposition[^\n]+?name\s*=\s*[\"']?(?P<name>[^\"'\r\n]+)[\"']?).+?\r?\n?)(((\r)?\n)+--)", req_info['data'])
        for param in param_tuple:
            req_poc_info = req_info.copy()
            req_poc_info['data'] = req_info['data'][:param.regs[1][0]] + param.group(1) + SQLMARK + req_info['data'][param.regs[1][1]:]
            if g_sql_info.check_mark_sql(req_poc_info) == 1:
                return 1
        exit()
    # json
    elif re.search(JSON_REGEX, req_info['data']):
        # 字符型
        param_tuple = re.finditer(r'("(?P<name>[^"]+)"\s*:\s*".*?)"(?<!\\")', req_info['data'])
        for param in param_tuple:
            req_poc_info = req_info.copy()
            req_poc_info['data'] = req_info['data'][:param.regs[1][0]] + param.group(1) + SQLMARK + req_info['data'][param.regs[1][1]:]
            if g_sql_info.check_mark_sql(req_poc_info) == 1:
                return 1
        #数字型 要把数字型加上双引号，不然没办法添加payload
        param_tuple = re.finditer(r'("(?P<name>[^"]+)"\s*:\s*)(-?\d[\d\.]*)\b', req_info['data'])
        for param in param_tuple:
            req_poc_info = req_info.copy()
            req_poc_info['data'] = req_info['data'][:param.regs[3][0]] + '"' + param.group(3) + SQLMARK +'"' + req_info['data'][param.regs[3][1]:]
            if g_sql_info.check_mark_sql(req_poc_info) == 1:
                return 1
        #数组型
        #param_tuple = re.finditer(r'("(?P<name>[^"]+)"\s*:\s*)((true|false|null))\b', req_info['data'])
        #列表型
        match = re.search(r'(?P<name>[^"]+)"\s*:\s*\[([^\]]+)\]', req_info['data'])
        if match:
            list_str = match.group(2)
            #列表中的字符型
            param_tuple = re.finditer(r'("[^"]+)"', list_str)
            for param in param_tuple:
                req_poc_info = req_info.copy()
                req_poc_info['data'] = req_info['data'].replace(list_str,list_str[:param.regs[1][0]] + param.group(1) + SQLMARK + list_str[param.regs[1][1]:])
                if g_sql_info.check_mark_sql(req_poc_info) == 1:
                    return 1
            #列表中的数字型
            param_tuple = re.finditer(r'(\A|,|\s+)(-?\d[\d\.]*\b)', list_str)
            for param in param_tuple:
                req_poc_info = req_info.copy()
                req_poc_info['data'] = req_info['data'].replace(list_str, list_str[:param.regs[2][0]] + '"' + param.group(2) + SQLMARK + '"' + list_str[param.regs[2][1]:])
                if g_sql_info.check_mark_sql(req_poc_info) == 1:
                    return 1
        exit()
    # xml类型
    elif re.search(XML_REGEX,req_info['data']):
        param_tuple = re.finditer(r"(<(?P<name>[^>]+)( [^<]*)?>)([^<]+)(</\2)", req_info['data'])
        for param in param_tuple:
            req_poc_info = req_info.copy()
            req_poc_info['data'] = req_poc_info['data'][:param.regs[4][0]] + param.group(4) + SQLMARK + req_poc_info['data'][param.regs[4][1]:]
            if g_sql_info.check_mark_sql(req_poc_info) == 1:
                return 1
        exit()

    #form注入检测
    if req_info['method'] == 'POST':
        #先循环参数再循环payload
        unquote_post_param_list = parse_data(req_info['data'])

        #解析url参数
        parse_url = urlparse.urlparse(req_info['url'])
        unquote_get_param_list = parse_data(parse_url.query)

        # post中data参数存在注入
        for param_index, param in enumerate(unquote_post_param_list):
            #people={"age":11,"name":"name"}，param[1]={"age":11}
            if re.search(JSON_REGEX, param[1]):
                #循环json里面的字符串类型
                json_param_tuple = re.finditer(r'("(?P<name>[^"]+)"\s*:\s*".*?)"(?<!\\")', param[1])
                for json_param in json_param_tuple:
                    poc_param_list = []
                    poc_param_list = poc_param_list + unquote_post_param_list
                    poc_json_param = param[1][:json_param.regs[1][0]] + json_param.group(1) + SQLMARK + param[1][json_param.regs[1][1]:]
                    
                    # 过滤垃圾参数如token等
                    gp_continue = 0
                    for gp in GARBAGE_PARAM:
                        if param[0] == gp:
                            gp_continue = 1
                    if gp_continue == 1:
                        continue
                    else:
                        # payload构造
                        if param_index == 0:
                            poc_param_list = [(param[0], poc_json_param)] + poc_param_list[param_index + 1:]
                        else:
                            poc_param_list = poc_param_list[0:param_index] + [(param[0], poc_json_param)] + poc_param_list[param_index + 1:]

                        def link(param):
                            return param[0] + '=' + param[1]

                        data = '&'.join(map(link, poc_param_list))

                        # 构造poc
                        req_poc_info = req_info.copy()
                        req_poc_info['data'] = data

                        # 进行标记检查
                        if g_sql_info.check_mark_sql(req_poc_info) == 1:
                            return 1

                # 循环json里面的数字类型
                json_param_tuple = re.finditer(r'("(?P<name>[^"]+)"\s*:\s*)(-?\d[\d\.]*)\b', param[1])
                for json_param in json_param_tuple:

                    poc_param_list = []
                    poc_param_list = poc_param_list + unquote_post_param_list
                    poc_json_param = param[1][:json_param.regs[3][0]] + '"' + json_param.group(3) + SQLMARK + '"' + param[1][json_param.regs[3][1]:]
                    # payload构造
                    if param_index == 0:
                        poc_param_list = [(param[0], '"' + poc_json_param + '"')] + poc_param_list[param_index + 1:]
                    else:
                        poc_param_list = poc_param_list[0:param_index] + [(param[0], poc_json_param)] + poc_param_list[param_index + 1:]

                    def link(param):
                        return param[0] + '=' + param[1]

                    data = '&'.join(map(link, poc_param_list))

                    # 构造poc
                    req_poc_info = req_info.copy()
                    req_poc_info['data'] = data

                    # 进行标记检查
                    if g_sql_info.check_mark_sql(req_poc_info) == 1:
                        return 1
            # post data参数检测
            else:
                poc_param_list = []
                poc_param_list = poc_param_list + unquote_post_param_list
                # payload构造
                if param_index == 0:
                    poc_param_list = [(param[0], param[1] + SQLMARK)] + poc_param_list[param_index + 1:]
                else:
                    poc_param_list = poc_param_list[0:param_index] + [(param[0], param[1] + SQLMARK)] + poc_param_list[param_index + 1:]

                def link(param):
                    return param[0] + '=' + param[1]

                data = '&'.join(map(link, poc_param_list))

                # 过滤垃圾参数如token等
                gp_continue = 0
                for gp in GARBAGE_PARAM:
                    if param[0] == gp:
                        gp_continue = 1
                if gp_continue == 1:
                    continue
                else:
                    # 构造poc
                    req_poc_info = req_info.copy()
                    req_poc_info['data'] = data

                    # 进行标记检查
                    if g_sql_info.check_mark_sql(req_poc_info) == 1:
                        return 1

        # post中url参数存在注入
        for param_index, param in enumerate(unquote_get_param_list):
            if len(unquote_get_param_list) > 0:
                # 循环参数
                poc_param_list = []
                poc_param_list = poc_param_list + unquote_get_param_list

                # 过滤垃圾参数如token等
                gp_continue = 0
                for gp in GARBAGE_PARAM:
                    if param[0] == gp:
                        gp_continue = 1
                if gp_continue == 1:
                    continue
                else:
                    # payload构造
                    if param_index == 0:
                        poc_param_list = [(param[0], param[1] + SQLMARK)] + poc_param_list[param_index + 1:]
                    else:
                        poc_param_list = poc_param_list[0:param_index] + [(param[0], param[1] + SQLMARK)] + poc_param_list[param_index + 1:]

                    def link(param):
                        return param[0] + '=' + param[1]

                    query = '&'.join(map(link, poc_param_list))

                    # 构造poc
                    req_poc_info = req_info.copy()
                    req_poc_info['url'] = parse_url.scheme + "://" + parse_url.netloc + parse_url.path + "?" + query

                    # 进行标记检查
                    if g_sql_info.check_mark_sql(req_poc_info) == 1:
                        return 1
    #url get注入检测
    if req_info['method'] == 'GET':
        parse_url = urlparse.urlparse(req_info['url'])
        quote_param_list = parse_data(parse_url.query)

        # 检测伪静态
        if parse_url.query == '':
            for digit in re.finditer(r'\d+', parse_url.path):
                mark_url = parse_url.scheme + "://" + parse_url.netloc + parse_url.path[:digit.regs[0][0]] + digit.group(0) + SQLMARK + parse_url.path[digit.regs[0][1]:]
                req_poc_info = req_info.copy()
                req_poc_info['url'] = mark_url
                if g_sql_info.check_mark_sql(req_poc_info) == 1:
                    return 1

        # 动态链接循环参数,len(quote_param_list) > 0用于有层次感，把这句去掉也可以的
        if len(quote_param_list) > 0:
            for param_index, param in enumerate(quote_param_list):
                poc_param_list = []
                poc_param_list = poc_param_list + quote_param_list

                # 过滤垃圾参数如token等
                gp_continue = 0
                for gp in GARBAGE_PARAM:
                    if param[0] == gp:
                        gp_continue = 1
                if gp_continue == 1:
                    continue
                else:
                # payload构造
                    if param_index == 0:
                        poc_param_list = [(param[0], param[1] + SQLMARK)] + poc_param_list[param_index + 1:]
                    else:
                        poc_param_list = poc_param_list[0:param_index] + [(param[0], param[1] + SQLMARK)] + poc_param_list[param_index + 1:]

                    def link(param):
                        return param[0] + '=' + param[1]

                    query = '&'.join(map(link, poc_param_list))

                    # 构造poc
                    req_poc_info = req_info.copy()
                    req_poc_info['url'] = parse_url.scheme + "://" + parse_url.netloc + parse_url.path + "?" + query

                    # 进行标记检查
                    if g_sql_info.check_mark_sql(req_poc_info) == 1:
                        return 1