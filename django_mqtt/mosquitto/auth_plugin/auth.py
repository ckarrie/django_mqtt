from django_mqtt.models import ACL, PROTO_MQTT_ACC_SUBSCRIBE, PROTO_MQTT_ACC_READ, PROTO_MQTT_ACC_WRITE
from django.conf import settings


def has_permission(user, topic, acc=None, clientid=None):
    """
    :param user: Active user
    :type user: django.contrib.auth.models.User
    :param topic:
    :type topic: str
    :param acc:
    :type acc: int
    :param clientid:
    :type clientid: django_mqtt.models.ClientId
    :return: If user have permission to access to topic
    :rtype: bool
    """

    allow = False

    if hasattr(settings, 'MQTT_ACL_ALLOW'):
        allow = settings.MQTT_ACL_ALLOW

    if hasattr(settings, 'MQTT_ACL_ALLOW_ANONIMOUS'):

        if user is None or user.is_anonymous:
            allow = settings.MQTT_ACL_ALLOW_ANONIMOUS & allow
            if not allow:
                return allow

    if user and not user.is_active:
        return allow

    acls = ACL.objects.filter(topic__name=topic)

    if acc is not None and acc > 0:

        if acc & PROTO_MQTT_ACC_READ == PROTO_MQTT_ACC_READ:
            acls = acls.filter(readable=PROTO_MQTT_ACC_READ)

        if acc & PROTO_MQTT_ACC_WRITE == PROTO_MQTT_ACC_WRITE:
            acls = acls.filter(writeable=PROTO_MQTT_ACC_WRITE)

        if acc & PROTO_MQTT_ACC_SUBSCRIBE == PROTO_MQTT_ACC_SUBSCRIBE:
            acls = acls.filter(subscribable=PROTO_MQTT_ACC_SUBSCRIBE)

        if acls.count() > 0:
            acl = acls.get()
            return acl.has_permission(user=user)

    # TODO search best candidate
    return ACL.get_default(acc, user=user)