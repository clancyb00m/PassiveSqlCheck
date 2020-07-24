# -*- coding: utf-8 -*-

"""
问题：
    1. 有的数据包并不能被解码
    2. tratio < UPPER_RATIO_BOUND and fratio < UPPER_RATIO_BOUND的情况，也是有可能存在注入的
更新：
    保持数据包不变，取消解码
"""

import sys
from func.check import check
from conf.setting import *
from func.common import read_xml_reqs

sys.dont_write_bytecode = True

def main():
    reqs = read_xml_reqs(args.file)
    for req in reqs:
        hostname = re.search('Host: (.*?)\n', req).group(1).strip()
        if args.host == []:
            check(req)
            g_sql_info.out_result()
            g_sql_info.mark_flag = False
            g_sql_info.result_list = []
            g_sql_info.rank += 1
        else:
            for host in args.host:
                if '*.' in host:
                    if host.replace('*.','') in hostname:
                        check(req)
                        g_sql_info.out_result()
                        g_sql_info.mark_flag = False
                        g_sql_info.result_list = []
                        g_sql_info.rank += 1
                else:
                    if host in hostname:
                        check(req)
                        g_sql_info.out_result()
                        g_sql_info.mark_flag = False
                        g_sql_info.result_list = []
                        g_sql_info.rank += 1

if __name__ == "__main__":
    main()