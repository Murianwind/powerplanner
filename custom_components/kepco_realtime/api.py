"""한전 파워플래너 API 클라이언트."""
from __future__ import annotations

import logging

import rsa
from bs4 import BeautifulSoup
from curl_cffi.requests import AsyncSession

from .const import INTRO_URL, LOGIN_URL, RECENT_USAGE_URL

_LOGGER = logging.getLogger(__name__)


def _rsa_encrypt(modulus_hex: str, exponent_hex: str, message: str) -> str:
    """RSA 공개키로 메시지를 PKCS#1 v1.5 패딩 방식으로 암호화합니다."""
    modulus = int(modulus_hex, 16)
    exponent = int(exponent_hex, 16)
    pub_key = rsa.PublicKey(modulus, exponent)
    encrypted = rsa.encrypt(message.encode("utf-8"), pub_key)
    return encrypted.hex()


class KepcoApiError(Exception):
    """API 오류 기본 클래스."""


class KepcoAuthError(KepcoApiError):
    """인증 오류."""


class KepcoApiClient:
    """한전 파워플래너 API 클라이언트."""

    def __init__(self, username: str, password: str) -> None:
        """클라이언트를 초기화합니다."""
        self._username = username
        self._password = password
        self._session: AsyncSession | None = None

    async def _get_session(self) -> AsyncSession:
        """세션을 반환합니다. 없으면 새로 만듭니다."""
        if self._session is None:
            self._session = AsyncSession(impersonate="chrome120")
        return self._session

    async def async_close(self) -> None:
        """세션을 종료합니다."""
        if self._session:
            await self._session.close()
            self._session = None

    async def async_login(self) -> bool:
        """파워플래너에 로그인합니다."""
        session = await self._get_session()

        try:
            resp = await session.get(INTRO_URL)
            resp.raise_for_status()
        except Exception as err:
            raise KepcoAuthError(f"인트로 페이지 접근 실패: {err}") from err

        soup = BeautifulSoup(resp.text, "html.parser")
        modulus_tag = soup.find("input", {"id": "RSAModulus"})
        exponent_tag = soup.find("input", {"id": "RSAExponent"})
        sessid_tag = soup.find("input", {"id": "SESSID"})

        if not modulus_tag or not exponent_tag or not sessid_tag:
            raise KepcoAuthError("RSA 키 또는 세션 ID를 찾을 수 없습니다.")

        modulus = modulus_tag["value"].strip()
        exponent = exponent_tag["value"].strip()
        sessid = sessid_tag["value"].strip()

        _LOGGER.debug("RSA 키 및 세션 ID 획득 완료")

        try:
            enc_id = _rsa_encrypt(modulus, exponent, self._username)
            enc_pw = _rsa_encrypt(modulus, exponent, self._password)
        except Exception as err:
            raise KepcoAuthError(f"RSA 암호화 실패: {err}") from err

        try:
            resp = await session.post(
                LOGIN_URL,
                data={
                    "USER_ID": f"{sessid}_{enc_id}",
                    "USER_PW": f"{sessid}_{enc_pw}",
                },
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Referer": INTRO_URL,
                    "Cookie": f"JSESSIONID={sessid}",
                },
                allow_redirects=True,
            )
        except Exception as err:
            raise KepcoAuthError(f"로그인 요청 실패: {err}") from err

        if "confirmInfo.do" in str(resp.url):
            _LOGGER.debug("로그인 성공")
            return True

        _LOGGER.error("로그인 실패: %s", resp.url)
        return False

async def async_get_realtime_usage(self) -> dict:
        """실시간 사용량 데이터를 가져옵니다."""
        session = await self._get_session()

        try:
            resp = await session.post(RECENT_USAGE_URL, json={})
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            _LOGGER.warning("API 호출 실패, 재로그인 시도")
            if not await self.async_login():
                raise KepcoAuthError("재로그인 실패")
            try:
                resp = await session.post(RECENT_USAGE_URL, json={})
                resp.raise_for_status()
                data = resp.json()
            except Exception as err:
                raise KepcoApiError(f"재시도 후에도 실패: {err}") from err

        # 실제 응답 구조 확인용 — 문제 파악 후 제거
        _LOGGER.warning("KEPCO API 전체 응답: %s", data)

        result = data.get("result", {})
        if not result:
            raise KepcoApiError("API 응답에 result 없음")

        return result
