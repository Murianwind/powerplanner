"""한전 실시간 사용량 설정 플로우."""
import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResult

from .api import KepcoApiClient, KepcoAuthError
from .const import DOMAIN


async def _validate_credentials(hass: HomeAssistant, username: str, password: str) -> bool:
    """입력된 계정으로 실제 로그인을 시도합니다."""
    client = KepcoApiClient(username, password)
    try:
        return await client.async_login()
    finally:
        await client.async_close()


class KepcoConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """설정 플로우: HA UI에서 아이디/비밀번호를 입력받습니다."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict | None = None
    ) -> FlowResult:
        errors: dict[str, str] = {}

        if user_input is not None:
            username = user_input["username"]
            password = user_input["password"]

            try:
                ok = await _validate_credentials(self.hass, username, password)
                if ok:
                    await self.async_set_unique_id(username)
                    self._abort_if_unique_id_configured()
                    return self.async_create_entry(
                        title=f"한전 ({username})",
                        data={"username": username, "password": password},
                    )
                errors["base"] = "invalid_auth"
            except KepcoAuthError:
                errors["base"] = "invalid_auth"
            except Exception:  # noqa: BLE001
                errors["base"] = "cannot_connect"

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema({
                vol.Required("username"): str,
                vol.Required("password"): str,
            }),
            errors=errors,
        )
