import operator
from functools import reduce

# import six
from django.db.models import F, IntegerField, ExpressionWrapper

from django_mqtt.validators import *
from django.contrib.auth.models import Group
from django.utils.translation import ugettext_lazy as _
from django.conf import settings
from django.db import models

from django_mqtt.protocol import WILDCARD_SINGLE_LEVEL, WILDCARD_MULTI_LEVEL
from django_mqtt.protocol import TOPIC_SEP, TOPIC_BEGINNING_DOLLAR

PROTO_MQTT_ACC_NONE = 0
PROTO_MQTT_ACC_READ = 1
PROTO_MQTT_ACC_WRITE = 2
PROTO_MQTT_ACC_SUBSCRIBE = 4

PROTO_MQTT_ACC_ALL = PROTO_MQTT_ACC_READ | PROTO_MQTT_ACC_WRITE | PROTO_MQTT_ACC_SUBSCRIBE

PROTO_MQTT_ACC = (
    (PROTO_MQTT_ACC_NONE, _('None')),
    (PROTO_MQTT_ACC_READ, _('Read')),
    (PROTO_MQTT_ACC_WRITE, _('Write')),
    (PROTO_MQTT_ACC_SUBSCRIBE, _('Subscribe')),
)

ALLOW_EMPTY_CLIENT_ID = False
if hasattr(settings, 'MQTT_ALLOW_EMPTY_CLIENT_ID'):
    ALLOW_EMPTY_CLIENT_ID = settings.MQTT_ALLOW_EMPTY_CLIENT_ID


class SecureSave(models.Model):
    class Meta:
        abstract = True

    def save(self, force_insert=False, force_update=False, using=None, update_fields=None):
        self.full_clean()
        return super(SecureSave, self).save(force_insert=force_insert, force_update=force_update,
                                            using=using, update_fields=update_fields)


class ClientId(SecureSave):
    name = models.CharField(max_length=23, db_index=True, blank=True, unique=True,
                            validators=[ClientIdValidator(valid_empty=ALLOW_EMPTY_CLIENT_ID)])
    users = models.ManyToManyField(settings.AUTH_USER_MODEL, blank=True)
    groups = models.ManyToManyField(Group, blank=True)

    def is_public(self):
        return self.users.count() == 0 and self.groups.count() == 0

    def has_permission(self, user):
        if not self.is_public():
            if user:
                if self.users.filter(pk=user.pk):
                    return True
                elif self.groups.filter(pk__in=user.groups.all().values_list('pk')).count() > 0:
                    return True
        return self.is_public()

    def __unicode__(self):
        return self.name

    def __str__(self):
        return self.name

    def clean(self):
        if not hasattr(settings, 'MQTT_ALLOW_EMPTY_CLIENT_ID') or not settings.MQTT_ALLOW_EMPTY_CLIENT_ID:
            if self.name == '':
                raise ValidationError('Empty client_id not allowed', code='invalid')


class Topic(SecureSave):
    name = models.CharField(max_length=1024, validators=[TopicValidator()], db_index=True, unique=True, blank=False)
    wildcard = models.BooleanField(default=False)
    dollar = models.BooleanField(default=False)

    def __unicode__(self):
        return self.name

    def __str__(self):
        return self.name

    def __eq__(self, other):
        if isinstance(other, Topic):
            return self.name == other.name
        # elif isinstance(other, six.string_types) or isinstance(other, six.text_type):
        #     return self.name == other
        elif isinstance(other, str):
            return self.name == other

        return False

    def __lt__(self, other):
        comp = None
        if isinstance(other, Topic):
            comp = other
        # elif isinstance(other, six.string_types) or isinstance(other, six.text_type):
        #     comp = Topic(name=other)
        elif isinstance(other, str):
            comp = Topic(name=other)

        if not comp or not comp.is_wildcard():
            return False

        return self in comp

    def __len__(self):
        return len(self.name)

    def __gt__(self, other):

        if not self.is_wildcard():
            return False

        if isinstance(other, Topic):
            return other in self
        # elif isinstance(other, six.string_types) or isinstance(other, six.text_type):
        #     return Topic(other) in self
        elif isinstance(other, str):
            return Topic(name=other) in self

        return False

    def is_wildcard(self):
        return WILDCARD_MULTI_LEVEL in str(self.name) or WILDCARD_SINGLE_LEVEL in str(self.name)

    def is_dollar(self):
        return str(self.name).startswith(TOPIC_BEGINNING_DOLLAR)

    def __contains__(self, item):
        comp = None

        if isinstance(item, Topic):
            comp = item
        # elif isinstance(item, six.string_types) or isinstance(item, six.text_type):
        #     comp = Topic(name=item)
        elif isinstance(item, str):
            comp = Topic(name=item)

        if comp is None:
            return False

        if self == comp:
            return True

        elif not self.is_wildcard():
            return False

        elif (self.is_dollar() and not comp.is_dollar()) or (comp.is_dollar() and not self.is_dollar()):
            return False

        my_parts = self.name.split(TOPIC_SEP)
        comp_parts = comp.name.split(TOPIC_SEP)

        if self.is_dollar():
            if my_parts[0] != comp_parts[0]:
                return False

        if len(comp_parts) < len(my_parts):
            # print("lengths are different")
            return False

        if not self.name.endswith(WILDCARD_MULTI_LEVEL) and len(comp_parts) > len(my_parts):
            # print("we don't end with a wild card and they're longer than us...")
            return False

        for me, them in zip(my_parts, comp_parts):
            if me == WILDCARD_SINGLE_LEVEL and them != '':
                if comp.is_wildcard() and them == WILDCARD_MULTI_LEVEL:
                    return False
            elif me == WILDCARD_MULTI_LEVEL:
                return True
            elif me != them:
                return False
        return True

        # iter_comp = iter(comp_parts)
        # for part in my_parts:
        #     compare = next(iter_comp)
        #
        #     if part == WILDCARD_SINGLE_LEVEL:
        #         if comp.is_wildcard() and compare == WILDCARD_MULTI_LEVEL:
        #             return False
        #     elif part == WILDCARD_MULTI_LEVEL:
        #         return True
        #
        #     elif part != compare:
        #         return False
        # return True

    def get_candidates(self):
        # TODO improve it
        candidates = Topic.objects.filter(dollar=self.is_dollar(), wildcard=False)
        init = Topic.objects.filter(dollar=self.is_dollar(), wildcard=False)
        topic = self.name
        multi = False
        if topic.endswith(WILDCARD_MULTI_LEVEL):
            topic = topic[:-1]
            multi = True

        parts = topic.split(WILDCARD_SINGLE_LEVEL)
        if len(parts) == 1:
            if len(topic) != 0:
                candidates = candidates.filter(name__startswith=topic)
        elif topic == WILDCARD_SINGLE_LEVEL:
            candidates = candidates.exclude(name__contains=TOPIC_SEP)
        else:
            if multi:
                ini = candidates.filter(name__startswith=parts[0])
                con = candidates.filter(name__contains=parts[-1])
                candidates = candidates.filter(name__startswith=parts[0], name__contains=parts[-1])
            else:
                candidates = candidates.filter(name__startswith=parts[0], name__endswith=parts[-1])
            for part in set(parts[1:-1]):
                candidates = candidates.filter(name__contains=part)
        return candidates

    def __iter__(self):
        if not self.is_wildcard():
            yield self
        else:
            for candidate in self.get_candidates().all():
                if candidate in self:
                    yield candidate

    def save(self, force_insert=False, force_update=False, using=None,
             update_fields=None):
        if not update_fields or 'wildcard' in update_fields:
            self.wildcard = self.is_wildcard()
        if not update_fields or 'dollar' in update_fields:
            self.dollar = self.is_dollar()
        return super(Topic, self).save(force_insert=force_insert, force_update=force_update,
                                       using=using, update_fields=update_fields)


class ACLManager(models.Manager):

    def get_queryset(self):
        qs = super(ACLManager, self).get_queryset()
        qs = qs.annotate(readable=ExpressionWrapper(F('acc').bitand(PROTO_MQTT_ACC_READ), output_field=IntegerField()))
        qs = qs.annotate(
            writeable=ExpressionWrapper(F('acc').bitand(PROTO_MQTT_ACC_WRITE), output_field=IntegerField()))
        qs = qs.annotate(
            subscribable=ExpressionWrapper(F('acc').bitand(PROTO_MQTT_ACC_SUBSCRIBE), output_field=IntegerField()))
        return qs

    def is_readable(self):
        return self.filter(readable=PROTO_MQTT_ACC_READ)

    def is_writable(self):
        return self.filter(writeable=PROTO_MQTT_ACC_WRITE)

    def is_subscribable(self):
        return self.filter(subscribable=PROTO_MQTT_ACC_SUBSCRIBE)


class ACL(models.Model):
    allow = models.BooleanField(default=True)
    topic = models.ForeignKey(Topic, on_delete=models.CASCADE)  # There is many of acc options by topic
    acc = models.IntegerField(choices=PROTO_MQTT_ACC)
    users = models.ManyToManyField(settings.AUTH_USER_MODEL, blank=True)
    groups = models.ManyToManyField(Group, blank=True)
    password = models.CharField(max_length=512, blank=True, null=True,
                                help_text='Only valid for connect')

    objects = ACLManager()

    class Meta:
        unique_together = ('topic', 'acc')

    @property
    def is_readable(self):
        return self.acc & PROTO_MQTT_ACC_READ == PROTO_MQTT_ACC_READ

    @classmethod
    def get_default(cls, acc, user=None, password=None):  # TODO rename
        allow = False
        if hasattr(settings, 'MQTT_ACL_ALLOW'):
            allow = settings.MQTT_ACL_ALLOW
        if hasattr(settings, 'MQTT_ACL_ALLOW_ANONIMOUS'):
            if user is None or user.is_anonymous:
                allow = settings.MQTT_ACL_ALLOW_ANONIMOUS & allow
                if not allow and not password:
                    return allow
        try:
            broadcast_topic = Topic.objects.get(name=WILDCARD_MULTI_LEVEL)
            broadcast = cls.objects.filter(topic=broadcast_topic)

            # if acc in dict(PROTO_MQTT_ACC).keys():
            #     if broadcast.filter(acc=acc).exists():
            #         broadcast_acl = broadcast.get(acc=acc)
            #         allow = broadcast_acl.has_permission(user=user, password=password)
            if acc is not None and acc > 0:

                if acc & PROTO_MQTT_ACC_READ == PROTO_MQTT_ACC_READ:
                    broadcast = broadcast.filter(readable=PROTO_MQTT_ACC_READ)

                if acc & PROTO_MQTT_ACC_WRITE == PROTO_MQTT_ACC_WRITE:
                    broadcast = broadcast.filter(writeable=PROTO_MQTT_ACC_WRITE)

                if acc & PROTO_MQTT_ACC_SUBSCRIBE == PROTO_MQTT_ACC_SUBSCRIBE:
                    broadcast = broadcast.filter(subscribable=PROTO_MQTT_ACC_SUBSCRIBE)

                if broadcast.count() > 0:
                    acl = broadcast.get()
                    return acl.has_permission(user=user, password=password)

            else:
                for acl in broadcast:
                    allow &= acl.has_permission(user=user, password=password)

        except Topic.DoesNotExist:
            pass
        return allow

    def __gt__(self, other):
        if isinstance(other, ACL):
            return self.topic > other.topic

    def __lt__(self, other):
        if isinstance(other, ACL):
            return self.topic < other.topic

    @classmethod
    def get_acl(cls, topic, acc=PROTO_MQTT_ACC_ALL):

        # if isinstance(topic, six.string_types) or isinstance(topic, six.text_type):
        if isinstance(topic, str):
            topic, is_new = Topic.objects.get_or_create(name=topic)
        elif not isinstance(topic, Topic):
            raise ValueError('topic must be Topic or String')

        candidates = []
        try:
            candidates = [ACL.objects.get(topic=topic)]
        except ACL.DoesNotExist:
            for candidate in cls.objects.filter(topic__wildcard=True):
                if topic in candidate.topic:
                    candidates.append(candidate)

        # TODO - filter the candidates by the requested access...
        if len(candidates) == 0:
            return None

        return min(candidates)

    def is_public(self):
        return self.users.count() == 0 and self.groups.count() == 0 and not self.password

    def has_permission(self, user=None, password=None):

        allow = False
        if self.is_public():
            allow = self.allow
        else:
            if user:
                if user in self.users.all():
                    allow = self.allow
                elif self.groups.filter(pk__in=user.groups.values_list('pk')).exists():
                    allow = self.allow
                else:
                    allow = not self.allow

            if self.password and password:
                allow = self.password == password

        return allow

    def __unicode__(self):
        acc = []
        for a in map(list, PROTO_MQTT_ACC):
            if a[0] & self.acc > 0:
                acc.append(a[1][0])
        return "ACL %s for %s" % ("".join(acc).lower(), self.topic)

    def __str__(self):
        acc = []
        for a in map(list, PROTO_MQTT_ACC):
            if a[0] & self.acc > 0:
                acc.append(a[1][0])
        return "ACL %s for %s" % ("".join(acc).lower(), self.topic)
