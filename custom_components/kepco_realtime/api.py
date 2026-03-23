"""한전 파워플래너 API 클라이언트."""
from __future__ import annotations

import logging
from urllib.parse import unquote

import rsa
from bs4 import BeautifulSoup
from curl_cffi.requests import AsyncSession

from .const import BASE_URL, INTRO_URL, LOGIN_URL, RECENT_USAGE_URL

_LOGGER = logging.getLogger(__name__)

_UA = "Mozilla/5.0 (Linux; Android 11.0; Surface Duo) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Mobile Safari/537.36"

_LOGIN_HEADERS = {
    "Content-Type": "application/x-www-form-urlencoded",
    "Referer": INTRO_URL,
    "Origin": BASE_URL,
    "User-Agent": _UA,
    "sec-ch-ua": '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
    "sec-ch-ua-mobile": "?1",
    "sec-ch-ua-platform": '"Android"',
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
    "DNT": "1",
}

_API_HEADERS = {
    "Accept": "application/json, text/javascript, */*; q=0.01",
    "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
    "Content-Type": "application/json",
    "Origin": BASE_URL,
    "Referer": f"{BASE_URL}/rm/rm0201.do?menu_id=O020101",
    "X-Requested-With": "XMLHttpRequest",
}


def _rsa_encrypt(modulus_hex: str, exponent_hex: str, message: str) -> str:
    """RSA 공개키로 메시지를 PKCS#1 v1.5 방식으로 암호화합니다."""
    pub_key = rsa.PublicKey(int(modulus_hex, 16), int(exponent_hex, 16))
    return rsa.encrypt(message.encode("utf-8"), pub_key).hex()


class KepcoApiError(Exception):
    """API 오류 기본 클래스."""


class KepcoAuthError(KepcoApiError):
    """인증 오류."""


class KepcoApiClient:
    """한전 파워플래너 API 클라이언트."""

    def __init__(self, username: str, password: str) -> None:
        self._username = username
        self._password = password
        self._session: AsyncSession | None = None

    async def _new_session(self) -> AsyncSession:
        """기존 세션을 닫고 새 세션을 만듭니다."""
        if self._session:
            try:
                await self._session.close()
            except Exception:
                pass
        self._session = AsyncSession(impersonate="chrome120")
        return self._session

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
        """파워플래너에 로그인합니다.

        로그인 흐름:
          1. intro.do GET → cookieRsa, cookieSsId, JSESSIONID 쿠키 획득
          2. cookieRsa(RSA Modulus)로 아이디/비밀번호 암호화
          3. chkUser.do POST → 사용자 검증 및 SSO 여부 확인
          4. /login POST → 세션 수립
        """
        session = await self._new_session()

        # 1단계: intro 페이지 접근
        try:
            resp = await session.get(
                INTRO_URL,
                headers={
                    "User-Agent": _UA,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
                },
            )
            resp.raise_for_status()
        except Exception as err:
            raise KepcoAuthError(f"인트로 페이지 접근 실패: {err}") from err

        cookie_rsa = session.cookies.get("cookieRsa")
        cookie_ss_id = unquote(session.cookies.get("cookieSsId", "")) or None
        exponent_tag = BeautifulSoup(resp.text, "html.parser").find("input", {"id": "RSAExponent"})

        if not cookie_rsa or not cookie_ss_id or not exponent_tag:
            raise KepcoAuthError("RSA 키 또는 세션 ID를 찾을 수 없습니다.")

        exponent = exponent_tag["value"].strip()

        # 2단계: RSA 암호화
        try:
            enc_id = _rsa_encrypt(cookie_rsa, exponent, self._username)
            enc_pw = _rsa_encrypt(cookie_rsa, exponent, self._password)
        except Exception as err:
            raise KepcoAuthError(f"RSA 암호화 실패: {err}") from err

        user_id = f"{cookie_ss_id}_{enc_id}"
        user_pw = f"{cookie_ss_id}_{enc_pw}"

        # 3단계: chkUser.do — 사용자 검증 및 SSO 여부 확인
        sso_id = "N"
        try:
            chk_resp = await session.post(
                f"{BASE_URL}/intro/chkUser.do",
                json={"USER_ID": user_id, "USER_PWD": user_pw, "USER_CI": "", "TYPE": "I"},
                headers={
                    "Content-Type": "application/json",
                    "Referer": INTRO_URL,
                    "X-Requested-With": "XMLHttpRequest",
                    "User-Agent": _UA,
                },
            )
            chk_data = chk_resp.json()
            if chk_data.get("result") == "success":
                sso_id = chk_data.get("USER_SSO_YN", "N")
            elif chk_data.get("result") == "addCustno":
                _LOGGER.error("고객번호 추가 필요 — 파워플래너 웹에서 먼저 설정해주세요.")
                return False
        except Exception as err:
            _LOGGER.warning("chkUser.do 호출 실패 (무시하고 진행): %s", err)

        # 4단계: 로그인 POST
        try:
            resp = await session.post(
                LOGIN_URL,
                data={"USER_ID": user_id, "USER_PWD": user_pw, "APT_YN": "N", "SSO_ID": sso_id},
                headers=_LOGIN_HEADERS,
                allow_redirects=True,
            )
        except Exception as err:
            raise KepcoAuthError(f"로그인 요청 실패: {err}") from err

        if "intro.do" not in str(resp.url):
            _LOGGER.info("로그인 성공")
            return True

        _LOGGER.error("로그인 실패: %s", resp.url)
        return False

    async def async_get_realtime_usage(self) -> dict:
        """실시간 사용량 데이터를 가져옵니다.

        세션이 만료된 경우 자동으로 재로그인합니다.
        """
        session = await self._get_session()

        try:
            resp = await session.post(
                RECENT_USAGE_URL,
                json={"menuType": "time", "TOU": False},
                headers=_API_HEADERS,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as err:
            _LOGGER.warning("API 호출 실패 (원인: %s), 재로그인 시도", err)
            if not await self.async_login():
                raise KepcoAuthError("재로그인 실패")
            try:
                resp = await (await self._get_session()).post(
                    RECENT_USAGE_URL,
                    json={"menuType": "time", "TOU": False},
                    headers=_API_HEADERS,
                )
                resp.raise_for_status()
                data = resp.json()
            except Exception as retry_err:
                raise KepcoApiError(f"재시도 후에도 실패: {retry_err}") from retry_err

        if not isinstance(data, dict):
            raise KepcoApiError(f"예상치 못한 응답 형식: {type(data)}")

        return data
