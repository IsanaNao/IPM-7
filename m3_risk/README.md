# M3 Unternehmensabgleich, Lieferkette und Risiko

M3 beantwortet für jede Meldung die Frage: **Betrifft das unser Unternehmen?**
Welche Systeme sind betroffen, wie hoch ist das Risiko und bis wann muss gehandelt werden?

> **Stand (PR 1):** Datenbankschema (`db/init/m3_initial.sql`) und diese Schnittstellenbeschreibung.
> Die Logik (Import, Abgleich, Risiko-Score) folgt in PR 2. Bis dahin gibt es nur `GET /health`.
> Feedback zur Schnittstelle bitte direkt im PR, vor allem zu den Views für M4 (Abschnitt 5).

---

## 1. Aufgabe und Abgrenzung

| M3 macht | M3 macht nicht |
|---|---|
| Inventar der Beispielfirma verwalten (Assets, Software, SBOM) | Meldungen abrufen oder übersetzen (M1) |
| Meldungen mit dem Inventar abgleichen | Meldungen analysieren oder Glaubwürdigkeit bewerten (M2) |
| Nachrechenbaren Risiko-Score berechnen | Oberfläche, Benachrichtigungen, Benutzer (M4) |
| Maßnahme und Frist regelbasiert ableiten | Automatische Behebung oder Incident Response |
| Handlungsempfehlung je Zielgruppe (lokales LLM formuliert nur) | |
| Jede Aussage mit Quelle belegen | |

**Regeln**
- M3 schreibt nur in das Schema `m3`. Tabellen von M1 (`public`) und M2 (`m2`) werden nur gelesen.
- Einziger Fremdschlüssel nach außen: `public.raw_items(id)`. Kein Verweis auf `cve_affected.id`.
- Interne Inventardaten verlassen das System nie (siehe Abschnitt 9).

## 2. Eingaben

### Von M1 (`public`)
| Tabelle | Genutzte Felder | Zweck |
|---|---|---|
| `raw_items` | `id`, `url`, `title`/`title_de`, `cve_ids`, `published_at` | Meldung und die darin genannten CVEs |
| `cve_facts` | `cvss_score`, `cvss_version`, `kev_listed`, `kev_due_date`, `epss_score`, `updated_at` | Risikofaktoren |
| `cve_affected` | `data_source`, `cpe`, `vendor`, `product`, `ecosystem`, `package_name`, `version_exact`, `version_start/end_including/excluding` | **Hauptgrundlage für den Abgleich** |

Versionen sind Text. Der Versionsvergleich passiert in M3 (Python). Nicht auswertbare Versionen gelten als `unknown`, **nie** als „nicht betroffen“.

### Von M2 (`m2`)
| Tabelle | Genutzte Felder | Zweck |
|---|---|---|
| `summaries` | `raw_item_id`, `category` | Zeile vorhanden = M2 fertig = M3 ist dran; Kategorie steuert den Abgleich |
| `trust_scores` | `trust_score` (0-1), `trust_label` | Faktor im Risiko-Score |
| `entities` | `entity_type`, `normalized_name` | Ersatzweg ohne CVE und Herstellerabgleich (Abschnitt 4) |

### Wann ist eine Meldung offen?
Eine Meldung ist für M3 offen, wenn sie in `m2.summaries` steht **und** in `m3.processing`
noch keine Zeile hat **oder** sich ein Fingerabdruck geändert hat (Abschnitt 8).

## 3. Verarbeitung nach Kategorie (aus M2)

| Kategorie | Abgleich in M3 |
|---|---|
| `VULNERABILITY`, `ATTACK` | Über CVE, Produkt und Version (Wege 1-4) |
| `REGULATION`, `GEOPOLITICS` | Über den Hersteller (`vendor_exposure`, Weg 5), z. B. Einschränkungen für einen Anbieter. Keine Version, Risiko höchstens `medium`, immer manuell prüfen |
| `OUTAGE`, `OTHER` | `skipped` (im Prototyp nicht abgeglichen) |

Ob eine Regulierung für das Unternehmen als Ganzes gilt (Branche, Land, z. B. NIS2), gehört ins
Konzept, nicht in den Prototyp.

## 4. Abgleich (Wege nach Priorität)

| Weg | Grundlage | `match_method` | Sicherheit |
|---|---|---|---|
| 1 | CVE der Meldung -> `cve_affected` (NVD-CPE) -> Komponente mit gleichem Hersteller/Produkt -> Versionsvergleich | `cpe_version` | hoch |
| 2 | CVE -> `cve_affected` (OSV-Paket) -> SBOM-Komponente über purl -> Versionsvergleich | `purl_version` | hoch |
| 3 | Produkt passt, Version nicht auswertbar | `cpe_product_only` | mittel, `version_status = unknown` |
| 4 | Keine CVE: Produktname aus M2-Entitäten | `name_only` | niedrig, manuell prüfen |
| 5 | Regulierung/Geopolitik: Hersteller aus M2-Entitäten | `vendor_exposure` | niedrig bis mittel, manuell prüfen |

- Treffer über eine Abhängigkeit (z. B. Bibliothek in einem Docker-Image) haben `is_direct = false`
  und einen `dependency_path` vom Image bis zur betroffenen Komponente.
- Kombinationen, die als Fehlalarm markiert sind (`m3.suppressions`), werden übersprungen.

## 5. Ausgabe für M4 (Views, nur lesen)

M4 liest **nur diese Views** und keine internen Tabellen. Intern kann sich M3 ändern,
solange die Spalten der Views gleich bleiben.

### `m3.findings_current`
Offene, bewertete Treffer auf aktiven Assets und Komponenten. Grundlage für Übersicht,
Detailansicht und Benachrichtigung.

### `m3.findings_history`
Gleiche Spalten, aber inklusive erledigter Treffer (`status = resolved`). Für Verlauf und Entwarnungen.

| Spalte | Bedeutung |
|---|---|
| `match_id`, `risk_assessment_id` | IDs des Treffers und der aktuellen Bewertung |
| `status`, `resolved_at`, `resolved_reason` | `open`/`resolved`; Grund z. B. `version_not_affected`, `component_removed`, `asset_deactivated`, `advisory_changed`, `suppressed` |
| `raw_item_id`, `title`, `url`, `published_at` | Meldung |
| `cve_id` | CVE (leer bei Herstellerabgleich) |
| `category`, `trust_score`, `trust_label` | Kategorie und Glaubwürdigkeit aus M2 (Stand der Bewertung) |
| `asset_id`, `asset_key`, `asset_name`, `criticality`, `internet_exposed`, `asset_is_active` | Betroffenes System |
| `component_id`, `component_name`, `component_vendor`, `component_version`, `component_is_active` | Betroffene Software |
| `dependency_path_names` | Pfad als Namen, z. B. `{n8n, axios}` |
| `match_method`, `confidence`, `version_status`, `is_direct` | Wie sicher der Treffer ist |
| `risk_score` (0-100), `risk_level` | `critical`, `high`, `medium`, `low`, `info` |
| `action_code`, `deadline_at` | Maßnahme und Frist (regelbasiert) |
| `factor_breakdown` | Beitrag jedes Faktors zum Score (JSON), für die Begründung in der UI |
| `assessed_at` | Zeitpunkt der Bewertung |
| `recommendations` | JSON: `{"it_security": "...", "management": "...", "executive": "..."}` |
| `evidence` | JSON-Liste der Belege: `claim_key`, `claim_text`, `source_kind`, `raw_item_id`, `source_url` |

**Benachrichtigung genau einmal:** M4 merkt sich je `risk_assessment_id`, ob schon benachrichtigt wurde.
Steigt das Risiko (z. B. CVE neu in CISA KEV), legt M3 eine **neue** Bewertung mit neuer ID an,
und M4 benachrichtigt automatisch erneut.

### `m3.assets_overview`
Für die Verwaltungsseite: Asset-Stammdaten, `active_component_count`, `open_finding_count`,
`highest_risk_level`, `top_level_components` (JSON).

## 6. Endpunkte

Alle Endpunkte außer `GET /health` brauchen den Header `X-API-Key` (Abschnitt 7).
Aufrufer sind nur n8n (`/run`) und M4 (Import, Fehlalarme). M3 ist von außen nicht erreichbar.

| Methode | Pfad | Aufrufer | Zweck |
|---|---|---|---|
| GET | `/health` | Docker | Lebenszeichen, ohne Key |
| POST | `/run` | n8n | Offene Meldungen abgleichen und bewerten |
| POST | `/import/assets` | M4 | Inventar als CSV (vollständiger Schnappschuss) |
| POST | `/import/sbom?asset_key=...` | M4 | CycloneDX-JSON (Syft) für ein Asset |
| POST | `/suppressions` | M4 | Treffer als Fehlalarm markieren |
| DELETE | `/suppressions/{id}` | M4 | Markierung aufheben (wird nur deaktiviert) |

### `POST /run`
Kein Body. Antwort: `{"processed": 12, "matched": 3, "no_match": 6, "skipped": 2, "failed": 1}`.
Ein Fehler bei einer Meldung stoppt den Lauf nicht: sie wird `failed`, `attempts + 1`, und beim nächsten Lauf erneut versucht.

### `POST /import/assets` (CSV)
Datei als `multipart/form-data`, UTF-8, Komma als Trennzeichen, Kopfzeile Pflicht.
**Eine Zeile = eine Software auf einem Asset.** Ein Asset darf mehrere Zeilen haben.

| Spalte | Pflicht | Werte |
|---|---|---|
| `asset_key` | ja | eindeutiger Schlüssel, z. B. `fw-01` |
| `name` | ja | Anzeigename |
| `asset_type` | ja | `server`, `firewall`, `vpn_gateway`, `client`, `mail_server`, `database`, `web_application`, `container_host`, `network_device`, `other` |
| `criticality` | ja | 1-5 (5 = geschäftskritisch) |
| `internet_exposed` | ja | `true` / `false` |
| `environment` | nein | `production` (Standard), `staging`, `test` |
| `owner_team` | nein | zuständiges Team |
| `vendor` | nein | Hersteller, z. B. `Fortinet` |
| `product` | ja | Produkt, z. B. `FortiOS` |
| `version` | nein | z. B. `7.2.4` |
| `component_type` | nein | `application` (Standard), `operating_system`, `firmware`, `library`, `ai_model`, `cloud_service`, `other` |
| `vendor_country` | nein | ISO-Ländercode, z. B. `US`, `DE` (für den Herstellerabgleich) |
| `cpe23` | nein | z. B. `cpe:2.3:o:fortinet:fortios:7.2.4:*:*:*:*:*:*:*`; wenn gesetzt, gelten Hersteller und Produkt aus der CPE |

Regeln:
1. Zeilen mit gleichem `asset_key` müssen dieselben Asset-Angaben haben (Name, Typ, Kritikalität, ...).
2. Je Asset jedes Produkt nur einmal (eine Version je Produkt).
3. **Schnappschuss:** Assets und Software, die in der Datei fehlen, werden deaktiviert (nicht gelöscht).
   Eine geänderte Version wird an derselben Komponente aktualisiert, dadurch werden bestehende Treffer neu geprüft.
4. Alles oder nichts: bei einem Fehler wird nichts gespeichert, die Antwort listet alle fehlerhaften Zeilen.

Antwort: `{"assets_created", "assets_updated", "assets_deactivated", "components_created", "components_updated", "components_deactivated"}`.

### `POST /import/sbom?asset_key=...`
CycloneDX-JSON von Syft (`syft <image> -o cyclonedx-json`). Komponenten werden mit Eltern-Komponente
gespeichert, damit indirekt betroffene Software gefunden wird. Dieselbe Datei (gleicher Hash) wird nicht doppelt importiert.

### `POST /suppressions`
Body: `{"component_id": 17, "match_key": "CVE-2024-21762", "reason": "Funktion nicht aktiv", "created_by": "analyst@..."}`.
`match_key` steht in jedem Treffer (`cve_id` oder `raw:<raw_item_id>`). Der Treffer wird mit
`resolved_reason = suppressed` geschlossen und beim erneuten Abgleich übersprungen.

## 7. Authentifizierung und Fehler

- Header `X-API-Key` muss `INTERNAL_API_KEY` aus `.env` entsprechen (wie bei M2). Ist kein Key konfiguriert,
  wird **jede** Anfrage abgelehnt. Vergleich mit `hmac.compare_digest`.
- Fehler immer als JSON `{"detail": "..."}` (FastAPI-Standard, wie bei M2).

| Code | Wann |
|---|---|
| 200 | Erfolg |
| 401 | `X-API-Key` fehlt oder ist falsch |
| 404 | `asset_key` (SBOM) oder `component_id` (Fehlalarm) existiert nicht |
| 409 | Ein `/run` läuft bereits (Thread-Lock und `pg_try_advisory_lock(42003003)`; M2 nutzt 42002002) |
| 413 | Datei zu groß (vorläufig 5 MB) |
| 415 | Falscher Dateityp (kein CSV bzw. kein CycloneDX-JSON) |
| 422 | Inhalt ungültig; Import zusätzlich mit `"errors": [{"row": 5, "field": "criticality", "message": "..."}]` |
| 500 | Unerwarteter Fehler: allgemeine Meldung, Details nur im Log, **keine Inventardaten in der Antwort** |

## 8. Neubewertung und Lebenszyklus

**Fingerabdrücke statt Zeitstempel.** Für jede Meldung speichert `m3.processing` zwei Hashes über die
tatsächlich genutzten Werte:

| Fingerabdruck | Enthält | Bei Änderung |
|---|---|---|
| `match_fingerprint` | CVEs der Meldung, Werte aus `cve_affected`, M2-Entitäten, Inventarstand | neu abgleichen und bewerten |
| `risk_fingerprint` | CVSS, KEV, EPSS, Trust-Score und -Label, Kategorie, Asset-Kritikalität und -Erreichbarkeit, Policy-Version | nur neu bewerten |

So werden auch Änderungen erkannt, wenn sich nur Werte ändern (z. B. CVE neu in KEV, neuer Trust-Score),
und unnötige Neuberechnungen vermieden, wenn sich nur ein Zeitstempel ändert.

**Treffer werden nie gelöscht.** Sie werden mit Grund geschlossen (`resolved_reason`). Jede neue Bewertung ist eine
neue Zeile in `risk_assessments`; genau eine ist `is_current`. Alle Eingangswerte werden als Schnappschuss
gespeichert, damit jeder Score später nachrechenbar ist.

Beispiel: Firewall wird von 7.2.4 auf 7.2.7 aktualisiert -> CSV neu importiert -> Version wird an der Komponente
geändert -> neuer Abgleich ergibt „nicht betroffen“ -> Treffer `resolved` mit `version_not_affected`
-> verschwindet aus `findings_current`, bleibt in `findings_history`.

## 9. Datenschutz

- Inventar, Software und SBOMs liegen nur in der lokalen Datenbank.
- M3 ruft **keine externen Dienste** auf. Alle externen Informationen kommen bereits aufbereitet von M1.
- Für Empfehlungstexte (PR 4) wird nur das lokale Ollama genutzt, und das Modell erhält nur ein festes
  Faktenpaket. Maßnahme und Frist berechnet M3 regelbasiert, das LLM formuliert nur.
- Fehlermeldungen enthalten keine Inventardaten.

## 10. Datenmodell

```mermaid
flowchart LR
    RI[public.raw_items] --> M[m3.matches]
    A[m3.assets] --> C[m3.sbom_components]
    C -->|parent_component_id| C
    C --> M
    C --> S[m3.suppressions]
    M --> R[m3.risk_assessments]
    R --> E[m3.recommendations]
    R --> V[m3.evidence]
    RI --> P[m3.processing]
    M2S[m2.summaries] -.->|offen + Kategorie| P
```

Wichtige Regeln stehen als Constraints direkt in der Datenbank, u. a.:
`vendor_exposure` höchstens `medium`; `resolved` nur mit Zeitpunkt und Grund; je Treffer genau eine aktuelle
Bewertung; `dependency_path` endet bei der betroffenen Komponente.

## 11. Tests

```sh
docker compose down -v
docker compose up -d postgres
docker compose exec -T postgres psql -U argos -d argos -v ON_ERROR_STOP=1 < m3_risk/tests/m3_schema_smoke.sql
```
PowerShell:
```powershell
Get-Content -Raw m3_risk\tests\m3_schema_smoke.sql | docker compose exec -T postgres psql -U argos -d argos -v ON_ERROR_STOP=1
```
Erwartet: `NOTICE:  M3 smoke test OK`. Alle Testdaten werden zurückgerollt.

## 12. Offene Punkte

| An | Frage / Hinweis |
|---|---|
| M4 | Passen CSV-Format, die drei Views und `/suppressions`? Sollen Entwarnungen (`resolved`) auch benachrichtigt werden? |
| M2 | Hinweis: Ältere Meldungen bekommen kein neues Trust-Score, wenn spätere Quellen sie bestätigen. M3 würde eine Aktualisierung automatisch übernehmen. |
| M2 | Hinweis: `entities.version_text` wird bisher nicht befüllt, daher ist der Ersatzweg ohne CVE nur auf Produktebene möglich. |
| M1 | Ab wann gibt es echte Daten? Bis dahin testet M3 mit synthetischen Daten. |
| Alle | Regulierung/Geopolitik nur über den Hersteller und immer mit manueller Prüfung, okay? |
