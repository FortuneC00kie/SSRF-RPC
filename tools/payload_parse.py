#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author  : mr.chery (mr.chery666@gmail.com)

import urlparse
import urllib
import re


def url_parse(url, payload, add=False):
    """
    将待检测的url中的参数循环替换为ssrf检测payload
    :param url: 待检测url
    :param payload: 检测payload
    :param add: 是否是附加模式
    :return:
    """
    url_list = []
    rs = urlparse.urlparse(url)
    query_dict = dict([(k, v[0]) for k, v in urlparse.parse_qs(rs.query).items()])
    query_old = dict([(k, v[0]) for k, v in urlparse.parse_qs(rs.query).items()])
    # replace
    for key in query_dict.keys():
        query_dict[key] = payload
        new_parts = list(rs)
        new_parts[4] = urllib.urlencode(query_dict)
        url_list.append((urlparse.urlunparse(new_parts), key))
        query_dict[key] = query_old[key]

    # add
    if add:
        for key in query_dict.keys():
            query_dict[key] += payload
            new_parts = list(rs)
            new_parts[4] = urllib.urlencode(query_dict)
            url_list.append((urlparse.urlunparse(new_parts), key))
            query_dict[key] = query_old[key]

    return url_list


def post_data_parse(data, payload, add=False):
    """
    replace post data values
    :param data:
    :param add:
    :param payload:
    :return:
    """
    results = []
    for match in re.finditer(r"((\A|[?&])(?P<parameter>[\w\[\]]+)=)(?P<value>[^&#]*)", data):
        if add:
            res = data.replace(match.group(0), "%s%s" % (match.group(0), payload))
            results.append((res, match.group("parameter")))

        res = data.replace(match.group(0), "%s%s" % (match.group(1), payload))
        results.append((res, match.group("parameter")))
    return results