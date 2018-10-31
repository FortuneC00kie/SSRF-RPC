# coding=utf-8
import yaml
import requests
import uuid
import time
from requests import Request, Session
from tools import payload_parse
GET, POST = "GET", "POST"


class SsrfCheck(object):
    def __init__(self, url, data):
        self.url = url
        self.data = data

    def test(self):
        """
        ssrf漏洞检测函数
        :return:
        """
        result = {}
        with open("config.yaml") as f:
            x = yaml.load(f)
        url = self.url
        test_number = str(uuid.uuid4())
        log_url = "http://" + x['dnslog-host'] + "/weblog/" + test_number
        api_url = "http://www.paxmac.com/api_token/?auth=" + x['api-key']

        method = (POST if self.data else GET)
        if self.data:
            urls = payload_parse.post_data_parse(self.data, payload=log_url)
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            for data, param in urls:
                s = Session()
                req = Request(method, url, data=data, headers=headers)
                prepped = req.prepare()
                s.send(prepped)
        else:
            urls = payload_parse.url_parse(url, log_url)
            for test_url, param in urls:
                s = Session()
                req = Request(method, test_url)
                prepped = req.prepare()
                s.send(prepped)

        time.sleep(3)
        res = requests.get(api_url)
        if test_number in res.text:
            result['vul'] = True
            result['param'] = param
            return result
        else:
            result['vul'] = False
            result['param'] = ""
            return result


