#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import glob
import json
import os
import re
import shutil
import traceback
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urljoin

BASE_URL = "https://service.carstensen.eu"


def ascii_log(msg: str) -> None:
    """Print ASCII-only log line with timestamp."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    safe = msg.encode("ascii", "ignore").decode("ascii")
    print(f"[{ts}] {safe}", flush=True)


def normalize_time_value(raw: Any) -> str:
    """Normalize time like '0800' or '800' to 'HH:MM'."""
    if raw is None:
        return ""
    s = str(raw).strip()
    if not s:
        return s

    # already has colon
    if ":" in s:
        return s

    # 4 digits -> HHMM
    if len(s) == 4 and s.isdigit():
        return f"{s[:2]}:{s[2:]}"

    # 3 digits -> HMM -> 0H:MM
    if len(s) == 3 and s.isdigit():
        return f"0{s[0]}:{s[1:]}"

    return s


def normalize_date_value(raw: Any) -> str:
    """Normalize date 'YYYY-MM-DD' to 'DD.MM.YYYY'."""
    if raw is None:
        return ""
    s = str(raw).strip()
    if not s:
        return s

    m = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})", s)
    if m:
        y, mm, dd = m.groups()
        return f"{dd}.{mm}.{y}"

    return s


def extract_form_payload_and_action(html: str) -> Tuple[Dict[str, Any], str]:
    """Extract form payload and action URL from CreateNewOrder page."""
    soup = BeautifulSoup(html, "html.parser")
    form = soup.find("form", {"id": "formCreateNewOrder"}) or \
           soup.find("form", attrs={"action": lambda x: x and "/Order/CreateNewOrder" in x})
    if not form:
        raise RuntimeError("CreateNewOrder form not found")

    action = form.get("action") or "/Order/CreateNewOrder"
    action_url = urljoin(BASE_URL, action)

    payload: Dict[str, Any] = {}

    # All <input>
    for inp in form.find_all("input"):
        name = inp.get("name")
        if not name:
            continue
        itype = (inp.get("type") or "text").lower()
        # unchecked checkboxes / radios -> skip
        if itype in ("checkbox", "radio") and not inp.has_attr("checked"):
            continue
        payload[name] = inp.get("value", "")

    # All <textarea>
    for ta in form.find_all("textarea"):
        name = ta.get("name")
        if name:
            payload[name] = ta.get_text() or ""

    # All <select>
    for sel in form.find_all("select"):
        name = sel.get("name")
        if not name:
            continue
        opt = sel.find("option", selected=True) or sel.find("option")
        payload[name] = opt.get("value", "") if opt else ""

    return payload, action_url


@dataclass
class FieldRule:
    """Mapping rule for one WebSped field."""
    sources: List[str] = field(default_factory=list)
    default: Optional[Any] = None
    required: bool = False


@dataclass
class DocumentRule:
    """Mapping rule for one document field."""
    sources: List[str] = field(default_factory=list)   # path to file
    doc_type_id: Optional[str] = None                 # default DocTypeId
    archive_id: Optional[str] = None
    folder_id: Optional[str] = None
    base_dir: Optional[str] = None

    # textual document type, e.g. DokumentenTYP
    type_sources: List[str] = field(default_factory=list)
    type_map: Dict[str, str] = field(default_factory=dict)  # map "EINGANGSBELEGE" -> "16"
    default_type: Optional[str] = None


def normalize_field_rule(raw: Any) -> FieldRule:
    """
    Convert config value to FieldRule.

    Supported forms:
    - scalar (string/number) -> constant default
    - dict with keys: sources / columns / default / required
    """
    if isinstance(raw, dict):
        sources = raw.get("sources") or raw.get("columns") or []
        if isinstance(sources, str):
            sources = [sources]
        default = raw.get("default")
        required = bool(raw.get("required", False))
        return FieldRule(sources=list(sources), default=default, required=required)
    elif raw is None:
        return FieldRule()
    else:
        # simple scalar constant
        return FieldRule(default=raw)


def normalize_document_rules(raw: Any) -> List[DocumentRule]:
    """Convert config 'documents' section to a list of DocumentRule."""
    rules: List[DocumentRule] = []
    if not raw:
        return rules

    docs = raw
    if isinstance(raw, dict):
        docs = raw.get("rows", [])

    if not isinstance(docs, list):
        return rules

    for item in docs:
        if not isinstance(item, dict):
            continue

        sources = item.get("sources") or []
        if isinstance(sources, str):
            sources = [sources]

        type_sources = item.get("type_sources") or []
        if isinstance(type_sources, str):
            type_sources = [type_sources]

        type_map = item.get("doc_type_map") or {}
        if not isinstance(type_map, dict):
            type_map = {}

        default_type = item.get("default_type")

        rule = DocumentRule(
            sources=list(sources),
            doc_type_id=str(item["doc_type_id"]) if "doc_type_id" in item else None,
            archive_id=str(item["archive_id"]) if "archive_id" in item else None,
            folder_id=str(item["folder_id"]) if "folder_id" in item else None,
            base_dir=item.get("base_dir"),
            type_sources=list(type_sources),
            type_map=dict(type_map),
            default_type=default_type,
        )
        rules.append(rule)

    return rules


def resolve_field(rule: FieldRule, record: Dict[str, Any], field_name: str) -> Optional[str]:
    """Resolve value for one WebSped field from record + default in rule."""
    # 1) try sources from record
    for src_name in rule.sources:
        if src_name in record:
            val = record.get(src_name)
            if val is not None:
                s = str(val).strip()
                if s != "":
                    return s

    # 2) fall back to default
    if rule.default is not None:
        val = rule.default
        if isinstance(val, str):
            s = val.strip()
        else:
            s = str(val).strip()
        if s != "":
            return s

    # 3) required field without value
    if rule.required:
        raise RuntimeError(f"Required field '{field_name}' is missing and has no default")

    return None


class WebSpedClient:
    """Low-level client for WebSped Web interface."""

    def __init__(self, username: str, password: str) -> None:
        self.username = username
        self.password = password
        self.session: Optional[requests.Session] = None

    def login(self) -> requests.Session:
        ascii_log(f"Login as {self.username}")
        s = requests.Session()
        s.headers.update({
            "Accept-Language": "de-DE,de;q=0.8,en;q=0.5",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        })
        s.cookies.set("_culture", "de-DE", domain="service.carstensen.eu")

        data = {
            "returnUrl": "",
            "UserName": self.username,
            "Password": self.password,
            "RememberMe": "false",
        }
        r = s.post(BASE_URL + "/Account/LogOn", data=data, allow_redirects=True)
        ascii_log(f"Login HTTP status {r.status_code}, url={r.url}")
        r.raise_for_status()
        self.session = s
        return s

    def get_session(self) -> requests.Session:
        if self.session is None:
            return self.login()
        return self.session

    def load_create_order_form(self, customer_id: str) -> requests.Response:
        s = self.get_session()
        params = {"CustomerId": customer_id} if customer_id else {}
        r = s.get(BASE_URL + "/Order/CreateNewOrder", params=params)
        ascii_log(f"CreateNewOrder form HTTP status {r.status_code}, url={r.url}")
        r.raise_for_status()
        if "/Order/NotFound" in r.url:
            with open("debug_notfound.html", "w", encoding="utf-8") as f:
                f.write(r.text)
            raise RuntimeError("CreateNewOrder returned /Order/NotFound. Check CustomerId or permissions.")
        return r

    def create_position(self, session_id: str, pos_payload: Dict[str, Any]) -> None:
        """Create one goods position via AJAX."""
        s = self.get_session()
        url = f"{BASE_URL}/Order/CreateNewOrderPosition"
        params = {"SessionId": session_id}

        data: Dict[str, Any] = {
            "models[0].Id": "",
            "models[0].DetailId": "0",
            "models[0].OrderId": "0",
            "models[0].AS400Id": "",
            "models[0].LocalityId": "0",
            "models[0].SenderLocalityId": "0",
            "models[0].ConsigneeLocalityId": "0",
            "models[0].RowValue": "1",
            "models[0].ColValue": "0",
            "models[0].Content": "",
            "models[0].Packages": "",
            "models[0].PackageId": "",
            "models[0].Weight": "",
            "models[0].Length": "",
            "models[0].Width": "",
            "models[0].Height": "",
            "models[0].IsDangeroursGoods": "false",
            "models[0].TransportInOwnAccount": "false",
            "models[0].DangerousGoodsCount": "0",
            "models[0].SenderReceiverFlag": "S",
        }

        for key, value in pos_payload.items():
            if value is None:
                continue
            k = key.strip()
            if not k:
                continue
            data[f"models[0].{k}"] = str(value)

        r = s.post(url, params=params, data=data)
        ascii_log(f"Create position HTTP status {r.status_code}")
        r.raise_for_status()

    def upload_document(
        self,
        file_path: Path,
        doc_type_id: str = "16",
        archive_id: str = "1",
        folder_id: str = "2",
        session_field_name: str = "WEBSPED_CREATENEWORDER_DOCUMENTS",
        referer_url: Optional[str] = None,
    ) -> None:
        """Upload one document to temporary DMS storage for current session.

        We send the same fields that the browser sends from the CreateNewOrder
        page:
        - multipart/form-data with field name "UploadedDocuments"
        - DocTypeId as form field
        - SessionFieldName/ArchiveId/FolderId in query string
        No SessionId / RequestVerificationToken are included here, because
        they are not sent by the browser for this endpoint.
        """
        s = self.get_session()

        file_path = Path(file_path)
        if not file_path.is_file():
            ascii_log(f"WARNING: document file not found: {file_path}")
            return

        params = {
            "SessionFieldName": session_field_name,
            "ArchiveId": str(archive_id),
            "FolderId": str(folder_id),
        }
        data = {
            "DocTypeId": str(doc_type_id),
        }

        headers: Dict[str, str] = {}
        if referer_url:
            headers["Referer"] = referer_url

        with open(file_path, "rb") as f:
            files = {
                "UploadedDocuments": (file_path.name, f, "application/pdf"),
            }
            r = s.post(
                BASE_URL + "/DMS/UploadDocument",
                params=params,
                data=data,
                files=files,
                headers=headers or None,
            )

        ascii_log(
            f"UploadDocument HTTP status {r.status_code} for {file_path.name} "
            f"(DocTypeId={doc_type_id}, ArchiveId={archive_id}, FolderId={folder_id})"
        )
        try:
            snippet = (r.text or "").replace("", " ").replace("", " ")
            ascii_log(f"UploadDocument response snippet: {snippet[:200]}")
        except Exception:
            pass

        r.raise_for_status()

        # After successful upload, move source PDF to backup archive folder
        try:
            backup_dir = Path(r"e:\_Scripte\py\WEBSPED\BCK")
            backup_dir.mkdir(parents=True, exist_ok=True)
            date_prefix = datetime.now().strftime("%Y%m%d")
            new_name = f"{date_prefix}_{file_path.name}"
            dst = backup_dir / new_name
            shutil.move(str(file_path), str(dst))
            ascii_log(f"Moved document to {dst}")
        except Exception as e:
            ascii_log(f"ERROR moving document {file_path} to backup: {e}")

    def create_order(
        self,
        customer_id: str,
        header_payload: Dict[str, Any],
        positions: List[Dict[str, Any]],
        documents: Optional[List[Dict[str, Any]]] = None,
    ) -> Tuple[str, str]:
        """
        Create one order header with positions and optional documents.

        documents: list of dicts with keys:
          - path: Path
          - doc_type_id (optional)
          - archive_id (optional)
          - folder_id (optional)
        """
        # 1) Load form and base payload
        r = self.load_create_order_form(customer_id)
        base_payload, action_url = extract_form_payload_and_action(r.text)
        session_id = base_payload.get("SessionId", "")
        ascii_log(f"SessionId: {session_id}")

        # 2) Create positions
        for pos in positions:
            self.create_position(session_id, pos)

        # 3) Build header payload and create order
        payload = base_payload.copy()
        payload.update(header_payload or {})
        payload.setdefault("OrderId", "0")
        payload.setdefault("IsNew", "True")
        payload.setdefault("OrderNo", payload.get("OrderNo", "0"))

        ascii_log(
            "FreightPayer before POST: "
            f"Id={payload.get('FreightPayer.WebSpedCustomerId')}, "
            f"Name1={payload.get('FreightPayerName1')}, "
            f"Street={payload.get('FreightPayerStreet')}, "
            f"Zip={payload.get('FreightPayerLocality.Zip')}, "
            f"City={payload.get('FreightPayerLocality.City')}"
        )

        s = self.get_session()
        r = s.post(action_url, data=payload, allow_redirects=True)
        ascii_log(f"CreateNewOrder POST HTTP status {r.status_code}, url={r.url}")

        # 5) Check success redirect
        if "CreateNewOrderSuccess" in r.url:
            parsed = urlparse(r.url)
            qs = parse_qs(parsed.query)
            order_no = qs.get("OrderNo", [""])[0]
            order_id = qs.get("OrderId", [""])[0]
            ascii_log(f"SUCCESS: Order created. OrderNo={order_no}, OrderId={order_id}")
            return order_no, order_id

        # 6) Try to extract validation errors
        soup = BeautifulSoup(r.text, "html.parser")
        err_div = soup.find("div", class_="validation-summary-errors")
        if err_div:
            msgs = " ".join(err_div.stripped_strings)
            ascii_log(f"VALIDATION ERROR: {msgs}")
            raise RuntimeError(f"VALIDATION ERROR: {msgs}")
        else:
            ascii_log("No validation-summary-errors block found. See debug_create.html")
            with open("debug_create.html", "w", encoding="utf-8") as f:
                f.write(r.text)
            raise RuntimeError("Unknown error while creating order; see debug_create.html")


    def load_edit_order_form(self, order_id: str) -> Tuple[Dict[str, Any], str]:
        """Open existing order in CreateNewOrder form (edit mode)."""
        s = self.get_session()
        params = {"OrderId": str(order_id)}
        r = s.get(BASE_URL + "/Order/CreateNewOrder", params=params)
        ascii_log(f"Edit order form HTTP status {r.status_code}, url={r.url}")
        r.raise_for_status()
        base_payload, action_url = extract_form_payload_and_action(r.text)
        return base_payload, action_url

    def load_document_overview(self, order_no: str) -> None:
        """Call DMS/DocumentOverview like WebSped does for an existing order."""
        s = self.get_session()
        params = {
            "KeyItemValue": str(order_no),
            "KeyItemType": "AufNr",
            "RoleName": "OrderEntry",
        }
        data = {
            "sort": "",
            "group": "",
            "filter": "",
        }
        r = s.post(
            BASE_URL + "/DMS/DocumentOverview",
            params=params,
            data=data,
        )
        ascii_log(f"DocumentOverview HTTP status {r.status_code}")
        r.raise_for_status()

    def attach_documents_to_order(
        self,
        order_no: str,
        order_id: str,
        documents: List[Dict[str, Any]],
    ) -> None:
        """Attach documents to an already created order."""
        if not documents:
            return

        # 1) Open order in edit mode
        base_payload, action_url = self.load_edit_order_form(order_id)

        # 2) Initialize DMS context for this order
        try:
            self.load_document_overview(order_no)
        except Exception as e:
            ascii_log(f"WARNING: DocumentOverview failed: {e}")

        # 3) Upload documents
        for doc in documents:
            path = Path(doc["path"])
            doc_type_id = (
                doc.get("doc_type_id")
                or doc.get("DocTypeId")
                or base_payload.get("cboDocType")
                or "16"
            )
            archive_id = doc.get("archive_id") or doc.get("ArchiveId") or "1"
            folder_id = doc.get("folder_id") or doc.get("FolderId") or "2"

            self.upload_document(
                file_path=path,
                doc_type_id=str(doc_type_id),
                archive_id=str(archive_id),
                folder_id=str(folder_id),
                referer_url=action_url,
            )

        # 4) Save order again so that DMS links are persisted
        s = self.get_session()
        r = s.post(action_url, data=base_payload, allow_redirects=True)
        ascii_log(
            f"Save order after DMS attach HTTP status {r.status_code}, url={r.url}"
        )

        if "CreateNewOrderSuccess" not in r.url:
            soup = BeautifulSoup(r.text, "html.parser")
            err_div = soup.find("div", class_="validation-summary-errors")
            if err_div:
                msgs = " ".join(err_div.stripped_strings)
                ascii_log(f"WARNING: validation after DMS attach: {msgs}")
            else:
                ascii_log(
                    "WARNING: unknown result after DMS attach; see debug_attach.html"
                )
                with open("debug_attach.html", "w", encoding="utf-8") as f:
                    f.write(r.text)


class OrderImporter:
    """High-level importer for CSV / JSON / XML files based on mapping JSON."""

    def __init__(self, cfg: Dict[str, Any]) -> None:
        self.cfg = cfg
        self.input_cfg = cfg.get("input", {}) or {}

        # Login rules (username/password)
        self.login_rules = self._parse_login_rules(cfg.get("login", {}))

        # CustomerId rule (may come from file or default)
        self.customer_rule = normalize_field_rule(cfg.get("customer_id", ""))

        # Header / position mapping (new style or fallback to old style)
        raw_header_fields = cfg.get("header_fields")
        raw_position_fields = cfg.get("position_fields")

        if raw_header_fields is None:
            header_fields_cfg: Dict[str, Dict[str, Any]] = {}
            for ws_field, src in (cfg.get("header_mapping") or {}).items():
                header_fields_cfg[ws_field] = {"sources": [src]}
            for ws_field, const_val in (cfg.get("header_constants") or {}).items():
                d = header_fields_cfg.get(ws_field, {})
                d["default"] = const_val
                header_fields_cfg[ws_field] = d
            raw_header_fields = header_fields_cfg

        if raw_position_fields is None:
            position_fields_cfg: Dict[str, Dict[str, Any]] = {}
            for ws_field, src in (cfg.get("position_mapping") or {}).items():
                position_fields_cfg[ws_field] = {"sources": [src]}
            for ws_field, const_val in (cfg.get("position_constants") or {}).items():
                d = position_fields_cfg.get(ws_field, {})
                d["default"] = const_val
                position_fields_cfg[ws_field] = d
            raw_position_fields = position_fields_cfg

        self.header_rules: Dict[str, FieldRule] = {
            ws_field: normalize_field_rule(rule)
            for ws_field, rule in (raw_header_fields or {}).items()
        }
        self.position_rules: Dict[str, FieldRule] = {
            ws_field: normalize_field_rule(rule)
            for ws_field, rule in (raw_position_fields or {}).items()
        }

        # Dangerous goods config
        self.dangerous_cfg: Dict[str, Any] = cfg.get("dangerous_goods") or {}

        # Documents rules
        self.document_rules: List[DocumentRule] = normalize_document_rules(cfg.get("documents"))

        # Input format
        fmt = (self.input_cfg.get("format") or "csv").lower()
        if fmt not in ("csv", "json", "xml"):
            raise RuntimeError(f"Unsupported input.format: {fmt}")
        self.input_format = fmt

        # Grouping config (for multi-position orders)
        self.grouping_cfg: Dict[str, Any] = cfg.get("order_grouping") or {}
        keys = self.grouping_cfg.get("key_fields") or self.grouping_cfg.get("keys") or []
        if isinstance(keys, str):
            keys = [keys]
        self.group_keys: List[str] = list(keys)

        # Cache of WebSpedClient per (username, password)
        self.clients: Dict[Tuple[str, str], WebSpedClient] = {}

    def _parse_login_rules(self, raw_login: Any) -> Dict[str, FieldRule]:
        if not raw_login or not isinstance(raw_login, dict):
            raise RuntimeError("login section must be a dict with username/password")

        username_cfg = raw_login.get("username")
        password_cfg = raw_login.get("password")

        username_rule = normalize_field_rule(username_cfg)
        password_rule = normalize_field_rule(password_cfg)

        if not username_rule.sources and username_rule.default is None:
            raise RuntimeError("login.username must have either sources or default")
        if not password_rule.sources and password_rule.default is None:
            raise RuntimeError("login.password must have either sources or default")

        return {
            "username": username_rule,
            "password": password_rule,
        }

    def _get_or_create_client(self, username: str, password: str) -> WebSpedClient:
        key = (username, password)
        client = self.clients.get(key)
        if client is None:
            client = WebSpedClient(username=username, password=password)
            client.login()
            self.clients[key] = client
        return client

    def _resolve_login_for_record(self, record: Dict[str, Any]) -> Tuple[str, str]:
        user = resolve_field(self.login_rules["username"], record, "login.username")
        pwd = resolve_field(self.login_rules["password"], record, "login.password")
        if not user or not pwd:
            raise RuntimeError("Cannot resolve login credentials for record")
        return str(user), str(pwd)

    def _resolve_customer_id_for_record(self, record: Dict[str, Any]) -> str:
        cust = resolve_field(self.customer_rule, record, "customer_id")
        if not cust:
            raise RuntimeError("customer_id is missing and has no default")
        return str(cust)

    def _build_header_payload_for_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        payload: Dict[str, Any] = {}
        for ws_field, rule in self.header_rules.items():
            val = resolve_field(rule, record, ws_field)
            if val is not None and val != "":
                payload[ws_field] = val

        # normalize times and dates to WebSped format
        for time_field in ("LoadingTime", "DeliveryTime"):
            if time_field in payload and payload[time_field]:
                payload[time_field] = normalize_time_value(payload[time_field])

        for date_field in ("LoadingDate", "DeliveryDate", "DeliveryDateFix", "DeliveryDateUntil"):
            if date_field in payload and payload[date_field]:
                payload[date_field] = normalize_date_value(payload[date_field])

        return payload

    def _apply_dangerous_goods(self, record: Dict[str, Any], pos: Dict[str, Any]) -> None:
        if not self.dangerous_cfg:
            return
        trigger_sources = self.dangerous_cfg.get("trigger_sources") or []
        flag_field = self.dangerous_cfg.get("flag_field", "IsDangeroursGoods")
        count_field = self.dangerous_cfg.get("count_field", "DangerousGoodsCount")

        for src_name in trigger_sources:
            val = record.get(src_name)
            if val is not None:
                s = str(val).strip()
                if s not in ("", "0"):
                    pos[flag_field] = "true"
                    if count_field not in pos or not str(pos[count_field]).strip():
                        pos[count_field] = "1"
                    break

    def _build_positions_for_record(self, record: Dict[str, Any]) -> List[Dict[str, Any]]:
        pos: Dict[str, Any] = {}
        for ws_field, rule in self.position_rules.items():
            val = resolve_field(rule, record, ws_field)
            if val is not None and val != "":
                pos[ws_field] = val

        if not pos:
            raise RuntimeError("No position data in record (position_fields are empty).")

        self._apply_dangerous_goods(record, pos)
        return [pos]

    def _build_documents_for_record(
        self,
        record: Dict[str, Any],
        header_payload: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        docs: List[Dict[str, Any]] = []
        if not self.document_rules:
            return docs

        global_base = self.input_cfg.get("documents_base_dir")

        for rule in self.document_rules:
            # 1) resolve file path
            full_path: Optional[Path] = None
            for src_name in rule.sources:
                raw = record.get(src_name)
                if raw is None:
                    continue
                path_str = str(raw).strip().strip('"').strip("'")
                if not path_str:
                    continue

                if os.path.isabs(path_str):
                    full_path = Path(path_str)
                else:
                    base_dir = rule.base_dir or global_base
                    if base_dir:
                        full_path = Path(base_dir) / path_str
                    else:
                        full_path = Path(path_str)
                break  # path found

            if full_path is None:
                continue  # no file for this rule

            # 2) textual doc type
            doc_type_text: Optional[str] = None
            for t_src in rule.type_sources:
                val = record.get(t_src)
                if val is None:
                    continue
                s = str(val).strip()
                if s:
                    doc_type_text = s
                    break

            if not doc_type_text and rule.default_type:
                doc_type_text = str(rule.default_type).strip()

            # 3) map to DocTypeId
            doc_type_id = rule.doc_type_id or header_payload.get("cboDocType") or "16"

            if doc_type_text and rule.type_map:
                key_upper = doc_type_text.upper()
                mapped = (
                    rule.type_map.get(doc_type_text) or
                    rule.type_map.get(key_upper) or
                    rule.type_map.get(doc_type_text.lower())
                )
                if mapped:
                    doc_type_id = str(mapped)

            archive_id = rule.archive_id or "1"
            folder_id = rule.folder_id or "2"

            ascii_log(
                f"Document: {full_path} type={doc_type_text or 'N/A'} DocTypeId={doc_type_id}"
            )

            docs.append({
                "path": full_path,
                "doc_type_id": str(doc_type_id),
                "archive_id": str(archive_id),
                "folder_id": str(folder_id),
            })

        return docs

    # --------- Input readers ---------

    def _iter_csv_records(self, path: Path):
        delimiter = self.input_cfg.get("delimiter", ";")
        encoding = self.input_cfg.get("encoding", "utf-8")
        with open(path, "r", encoding=encoding, newline="") as f:
            reader = csv.DictReader(f, delimiter=delimiter)
            for row in reader:
                yield row

    def _iter_json_records(self, path: Path):
        encoding = self.input_cfg.get("encoding", "utf-8")
        with open(path, "r", encoding=encoding) as f:
            data = json.load(f)

        key = self.input_cfg.get("json_records_key")
        if key and isinstance(data, dict):
            items = data.get(key, [])
        else:
            items = data

        if isinstance(items, dict):
            yield items
        elif isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    yield item

    def _iter_xml_records(self, path: Path):
        import xml.etree.ElementTree as ET

        def _flatten(elem, record: Dict[str, Any], prefix: str = ""):
            """Recursively flatten XML into dict keys like 'FBHeader.BookingCreator'."""
            for child in elem:
                tag = child.tag
                if "}" in tag:
                    tag = tag.split("}", 1)[1]  # strip namespace

                key = f"{prefix}.{tag}" if prefix else tag

                # text value
                text = (child.text or "").strip()
                if text:
                    record[key] = text

                # attributes (на всякий случай, если будут нужны)
                for attr_name, attr_val in child.attrib.items():
                    record[f"{key}.@{attr_name}"] = attr_val

                # recurse into children
                if list(child):
                    _flatten(child, record, key)

        tree = ET.parse(str(path))
        root = tree.getroot()
        record_xpath = self.input_cfg.get("xml_record_xpath")
        if not record_xpath:
            raise RuntimeError("input.xml_record_xpath is required for xml format")

        for elem in root.findall(record_xpath):
            record: Dict[str, Any] = {}
            # attributes на уровне <Booking>
            for attr_name, attr_val in elem.attrib.items():
                record[attr_name] = attr_val

            _flatten(elem, record, "")

            yield record


    def _iter_records_for_file(self, path: Path):
        if self.input_format == "csv":
            return self._iter_csv_records(path)
        if self.input_format == "json":
            return self._iter_json_records(path)
        if self.input_format == "xml":
            return self._iter_xml_records(path)
        raise RuntimeError(f"Unsupported input.format: {self.input_format}")

    # --------- Main per-file processing ---------

    def process_all_files(self) -> None:
        pattern = self.input_cfg.get("glob")
        if not pattern:
            raise RuntimeError("input.glob is not configured in JSON")
        files = sorted(glob.glob(pattern))
        ascii_log(f"Found {len(files)} file(s)")
        for fname in files:
            self._process_file(Path(fname))

    def _process_file(self, path: Path) -> None:
        ascii_log(f"Processing file: {path}")
        success = 0
        failed = 0

        try:
            records_iter = self._iter_records_for_file(path)
            records = list(records_iter)
        except Exception as e:
            ascii_log(f"ERROR preparing reader for {path}: {e}")
            self._move_on_error(path)
            return

        if not self.group_keys:
            # classic mode: one record -> one order
            for idx, record in enumerate(records, start=1):
                try:
                    self._process_order_records([record], f"rec#{idx}", path)
                    success += 1
                except Exception as e:
                    failed += 1
                    ascii_log(f"ERROR record {idx} in file {path.name}: {e}")
                    traceback.print_exc()
        else:
            # grouped mode: multiple records -> one order with many positions
            groups: Dict[Tuple[str, ...], List[Dict[str, Any]]] = {}
            for record in records:
                key = tuple(str(record.get(k, "") or "").strip() for k in self.group_keys)
                groups.setdefault(key, []).append(record)

            for idx, (key, recs) in enumerate(groups.items(), start=1):
                label = f"group#{idx} key={key}"
                try:
                    ascii_log(f"Processing {label} with {len(recs)} record(s)")
                    self._process_order_records(recs, label, path)
                    success += 1
                except Exception as e:
                    failed += 1
                    ascii_log(f"ERROR {label} in file {path.name}: {e}")
                    traceback.print_exc()

        ascii_log(f"File {path.name} finished: success={success}, failed={failed}")

        move_processed = bool(self.input_cfg.get("move_processed", False))
        if move_processed:
            if failed == 0:
                self._move_file(path, self.input_cfg.get("processed_dir"))
            else:
                self._move_file(path, self.input_cfg.get("error_dir"))

    def _process_order_records(
        self,
        records: List[Dict[str, Any]],
        label: str,
        path: Path
    ) -> None:
        if not records:
            return

        first = records[0]

        customer_id = self._resolve_customer_id_for_record(first)
        username, password = self._resolve_login_for_record(first)
        client = self._get_or_create_client(username, password)

        header_payload = self._build_header_payload_for_record(first)

        # Ensure freight payer (Frachtzahler) is set.
        # By default we set it to the same value as customer_id.
        fp_id_key = "FreightPayer.WebSpedCustomerId"
        if fp_id_key not in header_payload or not str(header_payload.get(fp_id_key) or "").strip():
            header_payload[fp_id_key] = customer_id

        # Copy freight payer address from Sender* if missing
        fp_map = {
            "FreightPayerName1": "SenderName1",
            "FreightPayerStreet": "SenderStreet",
            "FreightPayerLocality.CountryCode": "SenderLocality.CountryCode",
            "FreightPayerLocality.Zip": "SenderLocality.Zip",
            "FreightPayerLocality.City": "SenderLocality.City",
        }
        for dst, src in fp_map.items():
            if not str(header_payload.get(dst) or "").strip():
                val = header_payload.get(src)
                if val:
                    header_payload[dst] = val

        # positions: one per record
        positions: List[Dict[str, Any]] = []
        for rec in records:
            pos_list = self._build_positions_for_record(rec)
            positions.extend(pos_list)

        # documents (collect, deduplicate) ...
        docs_map: Dict[str, Dict[str, Any]] = {}
        for rec in records:
            rec_docs = self._build_documents_for_record(rec, header_payload)
            for d in rec_docs:
                p = str(d["path"])
                if p not in docs_map:
                    docs_map[p] = d

        documents = list(docs_map.values()) if docs_map else None

        ascii_log(
            f"Creating order for {label}: customer_id={customer_id}, "
            f"positions={len(positions)}, documents={len(documents) if documents else 0}"
        )

        order_no, order_id = client.create_order(
            customer_id,
            header_payload,
            positions,
            documents=documents,
        )
        ascii_log(
            f"Order created for {label}: OrderNo={order_no}, OrderId={order_id}"
        )

    def _move_file(self, src: Path, dst_dir: Optional[str]) -> None:
        if not dst_dir:
            return
        dst = Path(dst_dir)
        dst.mkdir(parents=True, exist_ok=True)
        date_prefix = datetime.now().strftime("%Y%m%d")
        dst_path = dst / f"{date_prefix}_{src.name}"
        try:
            shutil.move(str(src), str(dst_path))
            ascii_log(f"Moved file to {dst_path}")
        except Exception as e:
            ascii_log(f"ERROR moving file {src} to {dst_path}: {e}")

    def _move_on_error(self, path: Path) -> None:
        err_dir = self.input_cfg.get("error_dir")
        if not err_dir:
            return
        self._move_file(path, err_dir)


def load_config(config_path: str) -> Dict[str, Any]:
    ascii_log(f"Loading config from {config_path}")
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Create WebSped orders from mapping config")
    parser.add_argument("--config", required=True, help="Path to JSON mapping config")
    args = parser.parse_args(argv)

    try:
        cfg = load_config(args.config)
    except Exception as e:
        ascii_log(f"ERROR loading config: {e}")
        ascii_log("================ READY ================")
        return 1

    try:
        importer = OrderImporter(cfg)
        importer.process_all_files()
    except Exception as e:
        ascii_log(f"FATAL: {e}")
        traceback.print_exc()
        ascii_log("================ READY ================")
        return 1

    ascii_log("================ READY ================")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
