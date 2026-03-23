"""한전 실시간 사용량 커스텀 컴포넌트."""
from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady

from .api import KepcoApiClient, KepcoAuthError
from .const import DOMAIN
from .coordinator import KepcoCoordinator

PLATFORMS: list[str] = ["sensor"]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """HA가 이 컴포넌트를 로드할 때 호출됩니다."""
    username: str = entry.data["username"]
    password: str = entry.data["password"]

    client = KepcoApiClient(username, password)

    try:
        ok = await client.async_login()
        if not ok:
            await client.async_close()
            raise ConfigEntryNotReady("로그인 실패")
    except KepcoAuthError as err:
        await client.async_close()
        raise ConfigEntryNotReady(f"인증 오류: {err}") from err

    coordinator = KepcoCoordinator(hass, client)
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
