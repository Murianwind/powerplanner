"""한전 실시간 사용량 센서."""
from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import UnitOfEnergy
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import KepcoCoordinator


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """config_entry로부터 센서를 등록합니다."""
    coordinator: KepcoCoordinator = hass.data[DOMAIN][entry.entry_id]
    username = entry.data["username"]
    async_add_entities([KepcoRealtimeUsageSensor(coordinator, entry, username)])


class KepcoRealtimeUsageSensor(CoordinatorEntity, SensorEntity):
    """실시간 누적 사용량 센서."""

    _attr_device_class = SensorDeviceClass.ENERGY
    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_native_unit_of_measurement = UnitOfEnergy.KILO_WATT_HOUR
    _attr_icon = "mdi:flash"
    _attr_has_entity_name = True
    _attr_name = "실시간 사용량"

    def __init__(
        self,
        coordinator: KepcoCoordinator,
        entry: ConfigEntry,
        username: str,
    ):
        super().__init__(coordinator)
        self._username = username
        self._attr_unique_id = f"{DOMAIN}_{username}_realtime_usage"

        # HA 기기(Device)로 등록 — 설정 → 기기 및 서비스 → 기기 탭에서 표시됨
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, username)},
            name=f"한전 파워플래너 ({username})",
            manufacturer="한국전력공사",
            model="파워플래너",
            configuration_url="https://pp.kepco.co.kr",
        )

    @property
    def native_value(self) -> float | None:
        """현재 사용량 (kWh)을 반환합니다."""
        if not self.coordinator.data:
            return None
        try:
            raw = self.coordinator.data.get("F_AP_QT")
            return float(str(raw).replace(",", "")) if raw is not None else None
        except (ValueError, TypeError):
            return None

    @property
    def extra_state_attributes(self) -> dict:
        """추가 속성값."""
        if not self.coordinator.data:
            return {}
        d = self.coordinator.data
        return {
            "검침 시작일": d.get("START_DT"),
            "검침 종료일": d.get("END_DT"),
            "경과 일수": d.get("DT"),
            "총 검침 일수": d.get("ET"),
            "예상 사용량": d.get("PREDICT_TOT"),
            "실시간 요금": d.get("TOTAL_CHARGE"),
            "예상 요금": d.get("PREDICT_TOTAL_CHARGE"),
            "누진 단계": d.get("PREDICT_BILL_LEVEL"),
            "계약 종별": d.get("CNTR_KND_NM"),
        }
