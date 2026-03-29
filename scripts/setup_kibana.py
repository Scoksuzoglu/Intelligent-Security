# scripts/setup_kibana.py
# Kibana 7.17.x için index pattern + donut chart + dashboard otomatik kurar.
# Kullanım: python scripts/setup_kibana.py

import json
import time
import requests

KIBANA_URL = "http://localhost:5601"
HEADERS = {
    "kbn-xsrf": "true",
    "Content-Type": "application/json"
}


# ── Yardımcı ────────────────────────────────────────────────────────────────

def wait_for_kibana(timeout=120):
    print("⏳ Kibana bekleniyor...", end="", flush=True)
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(f"{KIBANA_URL}/api/status", timeout=5)
            if r.status_code == 200:
                print(" hazır.")
                return True
        except Exception:
            pass
        print(".", end="", flush=True)
        time.sleep(3)
    print(" zaman aşımı!")
    return False


def post(path, payload, description=""):
    url = f"{KIBANA_URL}{path}"
    r = requests.post(url, headers=HEADERS, json=payload, timeout=15)
    if r.status_code in (200, 201):
        print(f"  ✅ {description}")
        return r.json()
    else:
        print(f"  ⚠️  {description} → HTTP {r.status_code}: {r.text[:200]}")
        return None


def put(path, payload, description=""):
    url = f"{KIBANA_URL}{path}"
    r = requests.put(url, headers=HEADERS, json=payload, timeout=15)
    if r.status_code in (200, 201):
        print(f"  ✅ {description}")
        return r.json()
    else:
        print(f"  ⚠️  {description} → HTTP {r.status_code}: {r.text[:200]}")
        return None


# ── 1. Index Pattern ─────────────────────────────────────────────────────────

def create_index_pattern():
    print("\n📌 Index pattern oluşturuluyor: intsec-predictions")
    payload = {
        "attributes": {
            "title": "intsec-predictions",
            "timeFieldName": "timestamp"
        }
    }
    result = put(
        "/api/saved_objects/index-pattern/intsec-predictions",
        payload,
        "Index pattern: intsec-predictions"
    )
    return result is not None


# ── 2. Donut Chart Visualization ─────────────────────────────────────────────

def create_donut_chart():
    print("\n🍩 Donut chart oluşturuluyor: Saldırı Tipi Dağılımı")

    vis_state = {
        "title": "Saldiri Tipi Dagilimi",
        "type": "pie",
        "params": {
            "type": "pie",
            "addTooltip": True,
            "addLegend": True,
            "legendPosition": "right",
            "isDonut": True,          # donut modu
            "labels": {
                "show": True,
                "values": True,
                "last_level": True,
                "truncate": 100
            }
        },
        "aggs": [
            {
                "id": "1",
                "enabled": True,
                "type": "count",
                "schema": "metric",
                "params": {}
            },
            {
                "id": "2",
                "enabled": True,
                "type": "terms",
                "schema": "segment",
                "params": {
                    "field": "attack_type.keyword",
                    "size": 10,
                    "order": "desc",
                    "orderBy": "1"
                }
            }
        ]
    }

    payload = {
        "attributes": {
            "title": "Saldiri Tipi Dagilimi",
            "visState": json.dumps(vis_state),
            "uiStateJSON": "{}",
            "description": "Saldiri tipi bazinda donut chart",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "index": "intsec-predictions",
                    "query": {"match_all": {}},
                    "filter": []
                })
            }
        }
    }

    result = put(
        "/api/saved_objects/visualization/intsec-donut-chart",
        payload,
        "Donut chart: Saldırı Tipi Dağılımı"
    )
    return result is not None


# ── 3. Bar Chart: Saatlik Saldırı Trendi ─────────────────────────────────────

def create_trend_chart():
    print("\n📈 Bar chart oluşturuluyor: Saatlik Saldırı Trendi")

    vis_state = {
        "title": "Saatlik Saldiri Trendi",
        "type": "histogram",
        "params": {
            "type": "histogram",
            "grid": {"categoryLines": False},
            "categoryAxes": [
                {
                    "id": "CategoryAxis-1",
                    "type": "category",
                    "position": "bottom",
                    "show": True,
                    "labels": {"show": True, "truncate": 100}
                }
            ],
            "valueAxes": [
                {
                    "id": "ValueAxis-1",
                    "type": "value",
                    "position": "left",
                    "show": True,
                    "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100}
                }
            ],
            "seriesParams": [
                {
                    "show": True,
                    "type": "histogram",
                    "mode": "stacked",
                    "data": {"label": "Count", "id": "1"},
                    "valueAxis": "ValueAxis-1"
                }
            ],
            "addTooltip": True,
            "addLegend": True,
            "legendPosition": "right"
        },
        "aggs": [
            {
                "id": "1",
                "enabled": True,
                "type": "count",
                "schema": "metric",
                "params": {}
            },
            {
                "id": "2",
                "enabled": True,
                "type": "date_histogram",
                "schema": "segment",
                "params": {
                    "field": "timestamp",
                    "interval": "auto",
                    "min_doc_count": 1
                }
            },
            {
                "id": "3",
                "enabled": True,
                "type": "terms",
                "schema": "group",
                "params": {
                    "field": "attack_type.keyword",
                    "size": 6,
                    "order": "desc",
                    "orderBy": "1"
                }
            }
        ]
    }

    payload = {
        "attributes": {
            "title": "Saatlik Saldiri Trendi",
            "visState": json.dumps(vis_state),
            "uiStateJSON": "{}",
            "description": "Zaman bazli saldiri trendi",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "index": "intsec-predictions",
                    "query": {"match_all": {}},
                    "filter": []
                })
            }
        }
    }

    result = put(
        "/api/saved_objects/visualization/intsec-trend-chart",
        payload,
        "Bar chart: Saatlik Saldırı Trendi"
    )
    return result is not None


# ── 4. Metric: Toplam Saldırı Sayısı ─────────────────────────────────────────

def create_attack_metric():
    print("\n🔢 Metric oluşturuluyor: Toplam Saldırı Sayısı")

    vis_state = {
        "title": "Toplam Saldiri Sayisi",
        "type": "metric",
        "params": {
            "addTooltip": True,
            "addLegend": False,
            "type": "metric",
            "metric": {
                "percentageMode": False,
                "useRanges": False,
                "colorSchema": "Red to Green",
                "metricColorMode": "None",
                "colorsRange": [{"from": 0, "to": 10000}],
                "labels": {"show": True},
                "invertColors": False,
                "style": {
                    "bgFill": "#000",
                    "bgColor": False,
                    "labelColor": False,
                    "subText": "",
                    "fontSize": 60
                }
            }
        },
        "aggs": [
            {
                "id": "1",
                "enabled": True,
                "type": "count",
                "schema": "metric",
                "params": {}
            }
        ]
    }

    payload = {
        "attributes": {
            "title": "Toplam Saldiri Sayisi",
            "visState": json.dumps(vis_state),
            "uiStateJSON": "{}",
            "description": "Toplam saldiri sayisi metrigi",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "index": "intsec-predictions",
                    "query": {
                        "bool": {
                            "must_not": [
                                {"term": {"attack_type.keyword": "Benign"}}
                            ]
                        }
                    },
                    "filter": []
                })
            }
        }
    }

    result = put(
        "/api/saved_objects/visualization/intsec-attack-metric",
        payload,
        "Metric: Toplam Saldırı Sayısı"
    )
    return result is not None


# ── 5. Dashboard ──────────────────────────────────────────────────────────────

def create_dashboard():
    print("\n🖥️  Dashboard oluşturuluyor: INTSEC Dashboard")

    panels = [
        {
            "panelIndex": "1",
            "gridData": {"x": 0, "y": 0, "w": 24, "h": 15, "i": "1"},
            "version": "7.17.9",
            "type": "visualization",
            "id": "intsec-donut-chart",
            "embeddableConfig": {}
        },
        {
            "panelIndex": "2",
            "gridData": {"x": 24, "y": 0, "w": 24, "h": 15, "i": "2"},
            "version": "7.17.9",
            "type": "visualization",
            "id": "intsec-trend-chart",
            "embeddableConfig": {}
        },
        {
            "panelIndex": "3",
            "gridData": {"x": 0, "y": 15, "w": 12, "h": 8, "i": "3"},
            "version": "7.17.9",
            "type": "visualization",
            "id": "intsec-attack-metric",
            "embeddableConfig": {}
        }
    ]

    payload = {
        "attributes": {
            "title": "INTSEC Dashboard",
            "description": "AI-Enhanced Cyberattack Classifier - Gercek zamanli izleme",
            "panelsJSON": json.dumps(panels),
            "optionsJSON": json.dumps({
                "useMargins": True,
                "syncColors": False,
                "hidePanelTitles": False
            }),
            "timeRestore": False,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({"query": {"match_all": {}}, "filter": []})
            }
        },
        "references": [
            {"id": "intsec-donut-chart",   "name": "panel_1", "type": "visualization"},
            {"id": "intsec-trend-chart",   "name": "panel_2", "type": "visualization"},
            {"id": "intsec-attack-metric", "name": "panel_3", "type": "visualization"}
        ]
    }

    result = put(
        "/api/saved_objects/dashboard/intsec-main-dashboard",
        payload,
        "Dashboard: INTSEC Dashboard"
    )
    return result is not None


# ── Ana akış ──────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("🛡️  INTSEC - Kibana Setup Script")
    print("=" * 60)

    if not wait_for_kibana():
        print("\n❌ Kibana'ya ulaşılamadı. docker-compose up -d çalıştır.")
        return

    steps = [
        ("Index Pattern",          create_index_pattern),
        ("Donut Chart",            create_donut_chart),
        ("Trend Chart",            create_trend_chart),
        ("Attack Metric",          create_attack_metric),
        ("Dashboard",              create_dashboard),
    ]

    results = []
    for name, fn in steps:
        results.append((name, fn()))

    print("\n" + "=" * 60)
    print("📋 Sonuç:")
    all_ok = True
    for name, ok in results:
        icon = "✅" if ok else "❌"
        print(f"  {icon} {name}")
        if not ok:
            all_ok = False

    if all_ok:
        print(f"\n🎉 Kurulum tamamlandı!")
        print(f"   Kibana → http://localhost:5601")
        print(f"   Dashboard → http://localhost:5601/app/dashboards")
        print(f"   'INTSEC Dashboard' ara ve aç.")
    else:
        print("\n⚠️  Bazı adımlar başarısız. Kibana loglarını kontrol et.")


if __name__ == "__main__":
    main()
