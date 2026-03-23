"""한전 파워플래너 API 클라이언트."""
from __future__ import annotations

import logging
from urllib.parse import unquote

import rsa
from bs4 import BeautifulSoup
from curl_cffi.requests import AsyncSession

from .const import BASE_URL, INTRO_URL, LOGIN_URL, RECENT_USAGE_URL

_LOGGER = logging.getLogger(__name__)

_COMMON_HEADERS = {
    "Accept": "application/json, text/javascript, */*; q=0.01",
    "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
    "Content-Type": "application/json",
    "Origin": BASE_URL,
    "Referer": f"{BASE_URL}/rm/rm0201.do?menu_id=O020101",
    "X-Requested-With": "XMLHttpRequest",
}

_UA = "Mozilla/5.0 (Linux; Android 11.0; Surface Duo) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Mobile Safari/537.36"


def _rsa_encrypt(modulus_hex: str, exponent_hex: str, message: str) -> str:
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
        self._username = username
        self._password = password
        self._session: AsyncSession | None = None

    async def _new_session(self) -> AsyncSession:
        if self._session:
            try:
                await self._session.close()
            except Exception:
                pass
        self._session = AsyncSession(impersonate="chrome120")
        return self._session

    async def _get_session(self) -> AsyncSession:
        if self._session is None:
            self._session = AsyncSession(impersonate="chrome120")
        return self._session

    async def async_close(self) -> None:
        if self._session:
            await self._session.close()
            self._session = None

    async def async_login(self) -> bool:
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
        cookie_ss_id_raw = session.cookies.get("cookieSsId")
        cookie_ss_id = unquote(cookie_ss_id_raw) if cookie_ss_id_raw else None

        _LOGGER.warning("cookieSsId 디코딩: %s", cookie_ss_id[:30] if cookie_ss_id else None)

        soup = BeautifulSoup(resp.text, "html.parser")
        exponent_tag = soup.find("input", {"id": "RSAExponent"})

        if not cookie_rsa or not cookie_ss_id or not exponent_tag:
            _LOGGER.error(
                "쿠키 또는 RSAExponent 획득 실패 — cookieRsa=%s cookieSsId=%s exponent=%s",
                bool(cookie_rsa), bool(cookie_ss_id), bool(exponent_tag),
            )
            raise KepcoAuthError("RSA 키 또는 세션 ID를 찾을 수 없습니다.")

        exponent = exponent_tag["value"].strip()
        _LOGGER.warning("쿠키 획득 완료 — exponent: %s", exponent)

        # 2단계: RSA 암호화
        try:
            enc_id = _rsa_encrypt(cookie_rsa, exponent, self._username)
            enc_pw = _rsa_encrypt(cookie_rsa, exponent, self._password)
        except Exception as err:
            raise KepcoAuthError(f"RSA 암호화 실패: {err}") from err

        # 3단계: chkUser.do
        sso_id = "N"
        try:
            chk_resp = await session.post(
                f"{BASE_URL}/intro/chkUser.do",
                json={
                    "USER_ID": f"{cookie_ss_id}_{enc_id}",
                    "USER_PWD": f"{cookie_ss_id}_{enc_pw}",
                    "USER_CI": "",
                    "TYPE": "I",
                },
                headers={
                    "Content-Type": "application/json",
                    "Referer": INTRO_URL,
                    "X-Requested-With": "XMLHttpRequest",
                    "User-Agent": _UA,
                },
            )
            chk_data = chk_resp.json()
            _LOGGER.warning("chkUser 응답: %s", chk_data)
            result = chk_data.get("result", "")
            if result == "success":
                sso_id = chk_data.get("USER_SSO_YN", "N")
            elif result == "addCustno":
                _LOGGER.error("고객번호 추가 필요")
                return False
        except Exception as err:
            _LOGGER.warning("chkUser.do 호출 실패: %s", err)

        # 4단계: 로그인 POST
        try:
            resp = await session.post(
                LOGIN_URL,
                data={
                    "USER_ID": f"{cookie_ss_id}_{enc_id}",
                    "USER_PWD": f"{cookie_ss_id}_{enc_pw}",
                    "APT_YN": "N",
                    "SSO_ID": sso_id,
                },
                headers={
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
                },
                allow_redirects=True,
            )
        except Exception as err:
            raise KepcoAuthError(f"로그인 요청 실패: {err}") from err

        _LOGGER.warning("로그인 응답 url=%s status=%s", resp.url, resp.status_code)

        if "confirmInfo.do" in str(resp.url):
            _LOGGER.warning("로그인 성공!")
            return True

        fail_soup = BeautifulSoup(resp.text, "html.parser")
        status_tag = fail_soup.find("script", string=lambda t: t and "var status" in t if t else False)
        _LOGGER.error("로그인 실패 url=%s / status스크립트: %s",
                      resp.url,
                      status_tag.text[200:500] if status_tag else "없음")
        return False

    async def async_get_realtime_usage(self) -> dict:
        """실시간 사용량 데이터를 가져옵니다."""
        session = await self._get_session()

        try:
            resp = await session.post(
                RECENT_USAGE_URL,
                json={"menuType": "time", "TOU": False},
                headers=_COMMON_HEADERS,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as err:
            _LOGGER.warning("API 호출 실패 (원인: %s), 재로그인 시도", err)
            if not await self.async_login():
                raise KepcoAuthError("재로그인 실패")
            try:
                session = await self._get_session()
                resp = await session.post(
                    RECENT_USAGE_URL,
                    json={"menuType": "time", "TOU": False},
                    headers=_COMMON_HEADERS,
                )
                resp.raise_for_status()
                data = resp.json()
            except Exception as retry_err:
                raise KepcoApiError(f"재시도 후에도 실패: {retry_err}") from retry_err

        if not isinstance(data, dict):
            raise KepcoApiError(f"예상치 못한 응답 형식: {type(data)}")

        _LOGGER.warning("KEPCO API 응답: F_AP_QT=%s", data.get("F_AP_QT"))
        return data
