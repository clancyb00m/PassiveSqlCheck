# -*- coding: utf-8 -*-


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