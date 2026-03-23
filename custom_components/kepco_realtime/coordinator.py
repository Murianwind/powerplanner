"""데이터 갱신 코디네이터."""
from __future__ import annotations

import logging
from datetime import timedelta

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import KepcoApiClient, KepcoApiError, KepcoAuthError
from .const import DEFAULT_SCAN_INTERVAL, DOMAIN

_LOGGER = logging.getLogger(__name__)


class KepcoCoordinator(DataUpdateCoordinator[dict]):
    """지정된 주기마다 한전 API를 호출해 데이터를 갱신합니다."""

    def __init__(self, hass: HomeAssistant, client: KepcoApiClient) -> None:
        """코디네이터를 초기화합니다."""
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(minutes=DEFAULT_SCAN_INTERVAL),
        )
        self.client = client

    async def _async_update_data(self) -> dict:
        """HA가 주기적으로 호출하는 데이터 갱신 메서드."""
        try:
            return await self.client.async_get_realtime_usage()
        except KepcoAuthError as err:
            raise UpdateFailed(f"인증 오류: {err}") from err
        except KepcoApiError as err:
            raise UpdateFailed(f"API 오류: {err}") from err
