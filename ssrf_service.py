# coding=utf-8
import sys

reload(sys)
sys.setdefaultencoding("utf-8")

from nameko.rpc import rpc

import settings
from ssrf import connect, Job, JobSerializer
from ssrf import check, attack_method_switch
import logging

_log = logging.getLogger(__name__)


class SsrfExploitFramework(object):
    name = 'ssrf_framework'

    def __init__(self):
        """
        初始化数据库链接
        """
        connect(**settings.MONGODB)

    @rpc
    def rpc_start(self, enable_cache=False, attack=False, **kwargs):
        """
        启动rpc服务
        :param enable_cache: 是否在数据库缓存中查询结果
        :param attack: 是否开启攻击模式
        :param kwargs: 攻击参数
        :return:
        """
        _log.info("ssrf exploit framework start")
        url = kwargs.get("url")
        data = kwargs.get("data")
        if enable_cache:
            job = Job.objects(url=url).order_by('-created').first()
            return JobSerializer().dump(job).data
        if not attack:
            return check(url, data)
        return attack_method_switch(**kwargs)
