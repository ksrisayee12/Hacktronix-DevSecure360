import os
import time
import requests
from typing import Dict, List, Tuple

ZAP_API = os.getenv("ZAP_API", "http://127.0.0.1:8080")
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "12345")

def _params(extra: Dict = None) -> Dict:
    p = {}
    if ZAP_API_KEY:
        p["apikey"] = ZAP_API_KEY
    if extra:
        p.update(extra)
    return p

class ZapError(RuntimeError):
    pass

def trigger_zap_scan(target_url: str,
                     spider_timeout: int = 60,
                     ascan_timeout: int = 300,
                     poll_interval: int = 3) -> dict:

    try:
        v = requests.get(f"{ZAP_API}/JSON/core/view/version/", params=_params(), timeout=6)
        v.raise_for_status()

        a = requests.get(f"{ZAP_API}/JSON/core/action/accessUrl/", params=_params({"url": target_url}), timeout=8)
        a.raise_for_status()

        sp = requests.get(f"{ZAP_API}/JSON/spider/action/scan/", params=_params({"url": target_url, "maxChildren": 0}), timeout=8)
        sp.raise_for_status()
        spider_json = sp.json()
        spider_id = spider_json.get("scan") or spider_json.get("scanId") or spider_json.get("scanId2") or spider_json.get("scan_id")
        if spider_id is None:
            spider_id = None

        spider_elapsed = 0
        if spider_id is not None:
            while spider_elapsed < spider_timeout:
                st = requests.get(f"{ZAP_API}/JSON/spider/view/status/", params=_params({"scanId": spider_id}), timeout=8)
                st.raise_for_status()
                pct = int(st.json().get("status", 0))
                if pct >= 100:
                    break
                time.sleep(poll_interval)
                spider_elapsed += poll_interval
        else:
            time.sleep(min(5, spider_timeout))

        s = requests.get(
            f"{ZAP_API}/JSON/ascan/action/scan/",
            params=_params({"url": target_url, "recurse": True, "inScopeOnly": False}),
            timeout=10
        )
        s.raise_for_status()
        scan_json = s.json()
        scan_id = scan_json.get("scan")
        if scan_id is None:
            raise ZapError(f"Failed to start ascan (response: {scan_json})")

        ascan_elapsed = 0
        while ascan_elapsed < ascan_timeout:
            st = requests.get(f"{ZAP_API}/JSON/ascan/view/status/", params=_params({"scanId": scan_id}), timeout=8)
            st.raise_for_status()
            try:
                pct = int(st.json().get("status", 0))
            except Exception:
                pct = 0
            if pct >= 100:
                break
            time.sleep(poll_interval)
            ascan_elapsed += poll_interval

        alerts_resp = requests.get(f"{ZAP_API}/JSON/core/view/alerts/", params=_params({"baseurl": target_url}), timeout=15)
        alerts_resp.raise_for_status()
        alerts_by_base = alerts_resp.json()

        all_alerts_resp = requests.get(f"{ZAP_API}/JSON/core/view/alerts/", params=_params(), timeout=15)
        all_alerts_resp.raise_for_status()
        all_alerts = all_alerts_resp.json()

        alerts = alerts_by_base.get("alerts") if isinstance(alerts_by_base, dict) and "alerts" in alerts_by_base else []
        if not alerts:
            host = _extract_host(target_url)
            candidate = []
            for a in all_alerts.get("alerts", []) if isinstance(all_alerts, dict) else []:
                url = a.get("url", "") or (a.get("instance") or {}).get("uri", "")
                if host and host in (url or ""):
                    candidate.append(a)
            alerts = candidate

        return {
            "alerts": alerts,
            "meta": {
                "spider_id": spider_id,
                "spider_elapsed": spider_elapsed,
                "ascan_id": scan_id,
                "ascan_elapsed": ascan_elapsed,
                "requested_url": target_url
            }
        }

    except requests.exceptions.RequestException as re:
        raise ZapError(f"Cannot reach ZAP API at {ZAP_API}: {repr(re)}")
    except ZapError:
        raise
    except Exception as e:
        raise ZapError(str(e))


def parse_zap_alerts(alerts_json: dict) -> List[dict]:

    results: List[dict] = []
    alerts = alerts_json.get("alerts", []) if isinstance(alerts_json, dict) else alerts_json

    for a in alerts:
        results.append({
            "tool": "owasp_zap",
            "resource": a.get("url") or (a.get("instance") or {}).get("uri"),
            "issue": a.get("alert"),
            "severity": map_zap_risk(a.get("risk")),
            "confidence": a.get("confidence"),
            "description": a.get("description"),
            "cweid": a.get("cweid"),
            "reference": a.get("reference"),
            "evidence": a.get("evidence")
        })
    return results


def map_zap_risk(risk: str) -> str:
    if not risk:
        return "Medium"
    r = str(risk).lower()
    if "high" in r:
        return "High"
    if "medium" in r:
        return "Medium"
    return "Low"


def _extract_host(url: str) -> str:
    try:
        if "://" in url:
            host = url.split("://", 1)[1].split("/", 1)[0]
        else:
            host = url.split("/", 1)[0]
        return host
    except Exception:
        return ""
