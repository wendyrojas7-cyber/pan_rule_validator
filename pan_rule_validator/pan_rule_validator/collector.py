"""
collector.py
============

Thin client around Panorama's XML API. Responsible ONLY for authenticated
retrieval of raw configuration XML -- no parsing/resolution logic lives here
(that's normalizer.py). Keeping this stage dumb-and-simple makes it easy to
mock in tests and easy to swap for a different transport later (e.g. reading
from an offline config export instead of a live Panorama).

Security notes:
  - The service account used here should be a READ-ONLY Panorama admin role.
    This client never calls type=commit or any write/op action.
  - The API key should be generated once out-of-band and stored in a secrets
    manager (e.g. Azure Key Vault). This module accepts the key directly; it
    does not manage secret storage itself.
  - TLS verification is on by default. Only disable verify_ssl for a lab
    environment with a self-signed cert you've already validated out of band.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Optional

import requests
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)


class PanoramaAPIError(Exception):
    """Raised when Panorama returns status="error" or an HTTP-level failure."""


@dataclass
class PanoramaConfig:
    host: str                      # e.g. "panorama.internal.example.com"
    api_key: Optional[str] = None  # if not provided, use username/password once to mint one
    username: Optional[str] = None
    password: Optional[str] = None
    verify_ssl: bool = True
    timeout_seconds: int = 60
    max_retries: int = 3
    retry_backoff_seconds: float = 2.0


class PanoramaClient:
    """Minimal client for the parts of the PAN-OS XML API this pipeline needs:
    key generation and config retrieval (type=config&action=get).
    """

    def __init__(self, config: PanoramaConfig):
        self.config = config
        self._session = requests.Session()
        if config.api_key:
            self._api_key = config.api_key
        else:
            self._api_key = None  # lazily generated on first request

    @property
    def base_url(self) -> str:
        return f"https://{self.config.host}/api/"

    def _ensure_api_key(self) -> str:
        if self._api_key:
            return self._api_key
        if not (self.config.username and self.config.password):
            raise PanoramaAPIError(
                "No api_key provided and no username/password to mint one. "
                "Supply a pre-generated key from your secrets manager instead "
                "of embedding credentials where possible."
            )
        logger.info("Generating a new Panorama API key for %s", self.config.username)
        resp = self._session.get(
            self.base_url,
            params={
                "type": "keygen",
                "user": self.config.username,
                "password": self.config.password,
            },
            verify=self.config.verify_ssl,
            timeout=self.config.timeout_seconds,
        )
        root = self._parse_and_check(resp)
        key_el = root.find(".//key")
        if key_el is None or not key_el.text:
            raise PanoramaAPIError("keygen response did not contain a <key> element")
        self._api_key = key_el.text
        return self._api_key

    def _parse_and_check(self, resp: requests.Response) -> ET.Element:
        resp.raise_for_status()
        try:
            root = ET.fromstring(resp.text)
        except ET.ParseError as exc:
            raise PanoramaAPIError(f"Could not parse Panorama response as XML: {exc}") from exc

        status = root.attrib.get("status")
        if status != "success":
            msg_el = root.find(".//msg")
            detail = msg_el.text if msg_el is not None else resp.text[:500]
            raise PanoramaAPIError(f"Panorama API returned status={status!r}: {detail}")
        return root

    def get_config(self, xpath: str) -> ET.Element:
        """Fetch a config subtree at the given xpath (type=config&action=get).

        Returns the <result> element's first child (the actual config node),
        or an empty-children <result> if the xpath matched nothing.
        """
        key = self._ensure_api_key()
        params = {
            "type": "config",
            "action": "get",
            "xpath": xpath,
            "key": key,
        }

        last_exc: Optional[Exception] = None
        for attempt in range(1, self.config.max_retries + 1):
            try:
                resp = self._session.get(
                    self.base_url,
                    params=params,
                    verify=self.config.verify_ssl,
                    timeout=self.config.timeout_seconds,
                )
                root = self._parse_and_check(resp)
                result = root.find("result")
                return result if result is not None else root
            except (requests.RequestException, PanoramaAPIError) as exc:
                last_exc = exc
                logger.warning(
                    "Panorama get_config attempt %d/%d failed for xpath=%s: %s",
                    attempt, self.config.max_retries, xpath, exc,
                )
                if attempt < self.config.max_retries:
                    time.sleep(self.config.retry_backoff_seconds * attempt)
        assert last_exc is not None
        raise PanoramaAPIError(
            f"get_config failed after {self.config.max_retries} attempts for xpath={xpath}"
        ) from last_exc

    # -- convenience wrappers for the xpaths this pipeline actually needs -----

    def get_device_group_rulebase(self, device_group: str, pre_or_post: str = "pre-rulebase") -> ET.Element:
        if pre_or_post not in ("pre-rulebase", "post-rulebase"):
            raise ValueError("pre_or_post must be 'pre-rulebase' or 'post-rulebase'")
        xpath = (
            f"/config/devices/entry/device-group/entry[@name='{device_group}']"
            f"/{pre_or_post}/security/rules"
        )
        return self.get_config(xpath)

    def get_device_group_objects(self, device_group: str, kind: str) -> ET.Element:
        """kind is one of: address, address-group, service, service-group, application-group"""
        xpath = f"/config/devices/entry/device-group/entry[@name='{device_group}']/{kind}"
        return self.get_config(xpath)

    def get_shared_objects(self, kind: str) -> ET.Element:
        xpath = f"/config/shared/{kind}"
        return self.get_config(xpath)
