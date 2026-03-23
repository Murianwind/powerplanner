DOMAIN = "kepco_realtime"

# API URLs
BASE_URL = "https://pp.kepco.co.kr:8030"
INTRO_URL = f"{BASE_URL}/intro.do"
LOGIN_URL = f"{BASE_URL}/login"
RECENT_USAGE_URL = f"{BASE_URL}/low/main/getRM0201.do"

# 기본 업데이트 주기 (분)
DEFAULT_SCAN_INTERVAL = 30
