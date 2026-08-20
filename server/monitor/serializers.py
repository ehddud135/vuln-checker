from rest_framework import serializers

from .models import CheckResult, CheckRun, Host, MetricSample


class EnrollRequestSerializer(serializers.Serializer):
    code = serializers.CharField()
    hostname = serializers.CharField()
    ip = serializers.IPAddressField(required=False, allow_null=True)
    os = serializers.CharField(required=False, allow_blank=True)
    distro = serializers.CharField(required=False, allow_blank=True)


# max_length는 대응하는 모델 필드(models.py)의 max_length와 반드시 맞춘다 — 여기서
# 안 막으면 DB 레이어에서 bulk_create가 실패하고, 그 실패가 CheckRun 생성과 같은
# 트랜잭션에 묶여 있지 않던 시절엔 idempotency가 조용히 망가지는 원인이었다
# (adversarial review 지적 — P0, views.py의 트랜잭션 수정과 짝을 이루는 방어).
class CheckResultInputSerializer(serializers.Serializer):
    code = serializers.CharField(max_length=20)
    name = serializers.CharField(max_length=255)
    category = serializers.CharField(max_length=100, required=False, allow_blank=True)
    standard = serializers.CharField(max_length=20)
    status = serializers.ChoiceField(choices=["PASS", "FAIL", "REVIEW"])
    detail = serializers.CharField(required=False, allow_blank=True)
    reference = serializers.JSONField(required=False, default=dict)
    derived_from_codes = serializers.ListField(
        child=serializers.CharField(), required=False, default=list
    )


class ResultsSubmitSerializer(serializers.Serializer):
    run_id = serializers.CharField(max_length=64)
    profile = serializers.CharField(max_length=20)
    executed_at = serializers.DateTimeField()
    expected_count = serializers.IntegerField(required=False, default=0)
    results = CheckResultInputSerializer(many=True)


class MetricSampleInputSerializer(serializers.Serializer):
    metric_type = serializers.CharField(max_length=20)
    sub_dimension = serializers.CharField(max_length=100, required=False, allow_blank=True, default="")
    value = serializers.FloatField()
    unit = serializers.CharField(max_length=20, required=False, allow_blank=True, default="")
    kind = serializers.ChoiceField(choices=["gauge", "counter"], required=False, default="gauge")
    collected_at = serializers.DateTimeField()


class MetricsSubmitSerializer(serializers.Serializer):
    samples = MetricSampleInputSerializer(many=True)


class HostSerializer(serializers.ModelSerializer):
    class Meta:
        model = Host
        fields = ["id", "hostname", "ip", "os", "distro", "group", "last_heartbeat_at", "created_at"]


class CheckResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = CheckResult
        fields = [
            "code",
            "name",
            "category",
            "standard",
            "status",
            "detail",
            "reference",
            "derived_from_codes",
        ]


class CheckRunSerializer(serializers.ModelSerializer):
    results = CheckResultSerializer(many=True, read_only=True)

    class Meta:
        model = CheckRun
        fields = [
            "id",
            "profile",
            "executed_at",
            "pass_count",
            "fail_count",
            "review_count",
            "risk_score",
            "expected_count",
            "actual_count",
            "results",
        ]


class MetricSampleSerializer(serializers.ModelSerializer):
    class Meta:
        model = MetricSample
        fields = ["metric_type", "sub_dimension", "value", "unit", "kind", "collected_at"]
