async def async_login(self) -> bool:
    session = await self._new_session()

    # 1단계: intro 페이지 접근
    try:
        resp = await session.get(
            INTRO_URL,
            headers={
                "User-Agent": "Mozilla/5.0 (Linux; Android 11.0; Surface Duo) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Mobile Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
            },
        )
        resp.raise_for_status()
    except Exception as err:
        raise KepcoAuthError(f"인트로 페이지 접근 실패: {err}") from err

    _LOGGER.warning("intro.do 응답 Set-Cookie: %s", resp.headers.get("set-cookie", "없음"))
    _LOGGER.warning("세션 쿠키 목록: %s", dict(session.cookies))
    cookie_rsa = session.cookies.get("cookieRsa")
    cookie_ss_id = session.cookies.get("cookieSsId")
    jsessionid = session.cookies.get("JSESSIONID")

    soup = BeautifulSoup(resp.text, "html.parser")
    exponent_tag = soup.find("input", {"id": "RSAExponent"})

    if not cookie_rsa or not cookie_ss_id or not exponent_tag:
        _LOGGER.error(
            "쿠키 또는 RSAExponent 획득 실패 — cookieRsa=%s cookieSsId=%s exponent=%s",
            bool(cookie_rsa), bool(cookie_ss_id), bool(exponent_tag),
        )
        raise KepcoAuthError("RSA 키 또는 세션 ID를 찾을 수 없습니다.")

    exponent = exponent_tag["value"].strip()
    _LOGGER.warning(
        "쿠키 획득 — cookieSsId 앞20자: %s / JSESSIONID존재: %s / exponent: %s",
        cookie_ss_id[:20], bool(jsessionid), exponent,
    )

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
                "User-Agent": "Mozilla/5.0 (Linux; Android 11.0; Surface Duo) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Mobile Safari/537.36",
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

    # 4단계: 로그인 POST (브라우저와 동일한 헤더)
    login_data = {
        "USER_ID": f"{cookie_ss_id}_{enc_id}",
        "USER_PWD": f"{cookie_ss_id}_{enc_pw}",
        "APT_YN": "N",
        "SSO_ID": sso_id,
    }

    try:
        resp = await session.post(
            LOGIN_URL,
            data=login_data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": INTRO_URL,
                "Origin": BASE_URL,
                "User-Agent": "Mozilla/5.0 (Linux; Android 11.0; Surface Duo) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Mobile Safari/537.36",
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
