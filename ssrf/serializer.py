import marshmallow_mongoengine as serializers
from .documents import Job


class JobSerializer(serializers.ModelSchema):
    class Meta:
        model = Job
