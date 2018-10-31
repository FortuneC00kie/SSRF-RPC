# coding=utf-8
import datetime
import mongoengine as doc


def connect(host='mongodb://192.168.1.79/ssrf'):
    """
    mongo connection.
    :param host:
    :return:
    """
    doc.connect(host=host)


class Job(doc.Document):
    PENDING, RUNNING, FINISHED, TERMINATED, CACHED = ('pending', 'running', 'finished', 'terminated', 'cached')

    STATE = (
        (PENDING, "等待中"), (RUNNING, "创建中"), (FINISHED, "已完成"), (TERMINATED, "已中断"), (CACHED, "已缓存")
    )

    url = doc.StringField(max_length=255)
    data = doc.StringField(max_length=10000)
    param = doc.StringField(max_length=255)
    vulnerable = doc.BooleanField()
    ip_pool = doc.StringField(max_length=20)
    ip_port = doc.DictField(max_length=10000)
    redis_host = doc.StringField(max_length=20)
    redis_port = doc.StringField(max_length=20)
    shell_host = doc.StringField(max_length=20)
    shell_port = doc.StringField(max_length=20)
    authorized_keys = doc.StringField(max_length=300)
    cron_command = doc.StringField(max_length=100)
    payload_name = doc.StringField(max_length=20)
    payload_list = doc.DictField()
    payload_host = doc.StringField()
    state = doc.StringField(max_length=16, choices=STATE, default=PENDING)
    created = doc.DateTimeField(default=datetime.datetime.now)

    def __unicode__(self):
        return "{url}".format(url=self.url)
