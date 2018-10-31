#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author  : mr.chery (mr.chery666@gmail.com)
import urlparse
import urllib


def url_payload_set(url, param, payload):
    """
    替换URL中存在的ssrf漏洞的参数为payload
    :param payload: 攻击payload
    :return: 替换好的url
    """
    res = urlparse.urlparse(url)
    query_dict = dict([(k, v[0]) for k, v in urlparse.parse_qs(res.query).items()])
    query_dict[param] = payload
    a = list(res)
    a[4] = urllib.urlencode(query_dict)
    url = urlparse.urlunparse(a)
    return url