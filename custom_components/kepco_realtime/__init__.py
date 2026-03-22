"""한전 실시간 사용량 커스텀 컴포넌트."""
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .api import KepcoApiClient, KepcoAuthError
from .const import DOMAIN
from .coordinator import KepcoCoordinator

PLATFORMS = ["sensor"]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """HA가 이 컴포넌트를 로드할 때 호출됩니다."""
    username = entry.data["username"]
    password = entry.data["password"]

    client = KepcoApiClient(username, password)

    # 최초 로그인
    try:
        ok = await client.async_login()
        if not ok:
            return False
    except KepcoAuthError:
        return False

    coordinator = KepcoCoordinator(hass, client)

    # 첫 번째 데이터 갱신 (실패 시 예외 발생)
    await coordinator.async_config_entry_first_refresh()

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """컴포넌트 언로드 시 세션을 정리합니다."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        coordinator: KepcoCoordinator = hass.data[DOMAIN].pop(entry.entry_id)
        await coordinator.client.async_close()
    return unload_ok
