import logging

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.db import models

logger = logging.getLogger(__name__)


def _fernet() -> Fernet:
    return Fernet(settings.FIELD_ENCRYPTION_KEY)


class EncryptedTextField(models.TextField):
    """저장 시 Fernet(AES-128-CBC + HMAC)으로 암호화하고, 조회 시 복호화한다.

    이 필드를 도입하기 전에 평문으로 저장된 레코드는 복호화가 실패하므로, 그 경우는
    레거시 평문으로 간주해 원문을 그대로 반환한다 — 조용히 예외를 삼키는 게 아니라
    경고 로그를 남기고, 다음 저장 시점에 자연스럽게 암호화된 값으로 갱신된다.
    """

    def get_prep_value(self, value):
        if value is None or value == "":
            return value
        return _fernet().encrypt(value.encode()).decode()

    def from_db_value(self, value, expression, connection):
        if value is None or value == "":
            return value
        try:
            return _fernet().decrypt(value.encode()).decode()
        except (InvalidToken, ValueError):
            logger.warning(
                "EncryptedTextField: 복호화 실패 — 필드 도입 이전의 평문 레코드로 간주해 원문 반환"
            )
            return value
