#!/usr/bin/env python3
from __future__ import annotations

import argparse
import html
import json
import re
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from html.parser import HTMLParser
from http.cookiejar import CookieJar
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin
from urllib.request import HTTPCookieProcessor, Request, build_opener


ROOT = Path(__file__).resolve().parent.parent


class SmokeError(RuntimeError):
    pass


class FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.inputs: list[dict[str, str]] = []
        self.options: dict[str, list[dict[str, str]]] = {}
        self._select_name = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name: value or "" for name, value in attrs}
        if tag == "input":
            self.inputs.append(values)
        elif tag == "select":
            self._select_name = values.get("name", "")
            if self._select_name:
                self.options.setdefault(self._select_name, [])
        elif tag == "option" and self._select_name:
            self.options[self._select_name].append(values)

    def handle_endtag(self, tag: str) -> None:
        if tag == "select":
            self._select_name = ""

    def csrf_token(self) -> str:
        for item in self.inputs:
            if item.get("name") == "csrfmiddlewaretoken":
                return item.get("value", "")
        raise SmokeError("Could not find csrfmiddlewaretoken in form HTML.")

    def first_option_value(self, name: str) -> str:
        for item in self.options.get(name, []):
            value = item.get("value", "")
            if value:
                return value
        raise SmokeError(f"Could not find a selectable option for {name!r}.")


@dataclass
class SmokeHttpClient:
    base_url: str
    timeout: int

    def __post_init__(self) -> None:
        self.opener = build_opener(HTTPCookieProcessor(CookieJar()))

    def get(self, path: str) -> tuple[str, str]:
        request = Request(urljoin(self.base_url, path), headers={"User-Agent": "orc-compose-smoke/1"})
        with self.opener.open(request, timeout=self.timeout) as response:
            return response.geturl(), response.read().decode("utf-8", errors="replace")

    def get_json(self, path: str, *, token: str) -> dict[str, Any]:
        request = Request(
            urljoin(self.base_url, path),
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {token}",
                "User-Agent": "orc-compose-smoke/1",
            },
        )
        with self.opener.open(request, timeout=self.timeout) as response:
            return json.loads(response.read().decode("utf-8"))

    def post_form(self, path: str, fields: dict[str, Any]) -> tuple[str, str]:
        body = urlencode(fields).encode()
        request = Request(
            urljoin(self.base_url, path),
            data=body,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "orc-compose-smoke/1",
            },
        )
        with self.opener.open(request, timeout=self.timeout) as response:
            return response.geturl(), response.read().decode("utf-8", errors="replace")

    def post_json(self, path: str, fields: dict[str, Any], *, token: str) -> dict[str, Any]:
        request = Request(
            urljoin(self.base_url, path),
            data=json.dumps(fields).encode(),
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "User-Agent": "orc-compose-smoke/1",
            },
        )
        with self.opener.open(request, timeout=self.timeout) as response:
            return json.loads(response.read().decode("utf-8"))

    def post_multipart(
        self,
        path: str,
        fields: dict[str, Any],
        *,
        file_field: str,
        filename: str,
        content: bytes,
        content_type: str,
    ) -> tuple[str, str]:
        boundary = f"----orc-smoke-{uuid.uuid4().hex}"
        body = self._multipart_body(
            boundary=boundary,
            fields=fields,
            file_field=file_field,
            filename=filename,
            content=content,
            content_type=content_type,
        )
        request = Request(
            urljoin(self.base_url, path),
            data=body,
            headers={
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "User-Agent": "orc-compose-smoke/1",
            },
        )
        with self.opener.open(request, timeout=self.timeout) as response:
            return response.geturl(), response.read().decode("utf-8", errors="replace")

    def login(self, username: str, password: str) -> None:
        _, body = self.get("/accounts/login/")
        csrf = parse_form(body).csrf_token()
        url, body = self.post_form(
            "/accounts/login/",
            {
                "csrfmiddlewaretoken": csrf,
                "username": username,
                "password": password,
            },
        )
        if "/accounts/login/" in url or "Sign in" in body:
            raise SmokeError(f"Login failed for {username!r}.")

    @staticmethod
    def _multipart_body(
        *,
        boundary: str,
        fields: dict[str, Any],
        file_field: str,
        filename: str,
        content: bytes,
        content_type: str,
    ) -> bytes:
        chunks: list[bytes] = []
        for name, value in fields.items():
            chunks.extend(
                [
                    f"--{boundary}\r\n".encode(),
                    f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode(),
                    str(value).encode(),
                    b"\r\n",
                ]
            )
        chunks.extend(
            [
                f"--{boundary}\r\n".encode(),
                (
                    f'Content-Disposition: form-data; name="{file_field}"; '
                    f'filename="{filename}"\r\n'
                ).encode(),
                f"Content-Type: {content_type}\r\n\r\n".encode(),
                content,
                b"\r\n",
                f"--{boundary}--\r\n".encode(),
            ]
        )
        return b"".join(chunks)


def parse_form(body: str) -> FormParser:
    parser = FormParser()
    parser.feed(body)
    return parser


def run(command: list[str], *, check: bool = True, print_output: bool = True) -> subprocess.CompletedProcess[str]:
    print(f"+ {' '.join(command)}")
    result = subprocess.run(
        command,
        cwd=ROOT,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if result.stdout and print_output:
        print(result.stdout.rstrip())
    if check and result.returncode != 0:
        raise SmokeError(f"Command failed with exit code {result.returncode}: {' '.join(command)}")
    return result


def compose(
    args: argparse.Namespace,
    *compose_args: str,
    check: bool = True,
    print_output: bool = True,
) -> subprocess.CompletedProcess[str]:
    return run(
        [args.podman, "compose", "-f", str(args.compose_file), *compose_args],
        check=check,
        print_output=print_output,
    )


def compose_exec(
    args: argparse.Namespace,
    *service_args: str,
    check: bool = True,
    print_output: bool = True,
) -> subprocess.CompletedProcess[str]:
    return compose(args, "exec", "-T", args.service, *service_args, check=check, print_output=print_output)


def wait_for_app(client: SmokeHttpClient, timeout: int) -> None:
    deadline = time.monotonic() + timeout
    last_error = ""
    while time.monotonic() < deadline:
        try:
            _, body = client.get("/")
            if "Open Response Center" in body or "Sign in" in body:
                return
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            last_error = str(exc)
        time.sleep(2)
    raise SmokeError(f"App did not become ready within {timeout}s. Last error: {last_error}")


def submit_ticket(client: SmokeHttpClient) -> int:
    _, body = client.get("/tickets/new/")
    form = parse_form(body)
    marker = uuid.uuid4().hex[:8]
    url, body = client.post_multipart(
        "/tickets/new/",
        {
            "csrfmiddlewaretoken": form.csrf_token(),
            "title": f"Compose smoke ticket {marker}",
            "affected_system": form.first_option_value("affected_system"),
            "impact": "medium",
            "issue_summary": "Automated Compose smoke test submission.",
            "reproduction_steps": "1. Run scripts/compose_smoke_test.py.",
            "expected_outcome": "The deployed app accepts and tracks the ticket.",
            "actual_outcome": "Smoke test is exercising the deployed ticket path.",
            "additional_context": "Generated by the reusable deployment smoke test.",
        },
        file_field="file",
        filename=f"compose-smoke-{marker}.txt",
        content=b"Open Response Center Compose smoke-test attachment.\n",
        content_type="text/plain",
    )
    match = re.search(r"/tickets/(?P<ticket_id>\d+)/", url)
    if not match:
        match = re.search(r"Ticket #(?P<ticket_id>\d+)", body)
    if not match:
        raise SmokeError("Ticket submission did not redirect to a ticket detail page.")
    ticket_id = int(match.group("ticket_id"))
    if "Automated Compose smoke test submission." not in body:
        raise SmokeError("Ticket detail page did not render the smoke-test ticket.")
    return ticket_id


def operator_flow(client: SmokeHttpClient, ticket_id: int) -> None:
    _, body = client.get(f"/tickets/{ticket_id}/")
    csrf = parse_form(body).csrf_token()
    client.post_form(
        f"/operator/tickets/{ticket_id}/",
        {
            "csrfmiddlewaretoken": csrf,
            "status": "in_progress",
            "operator": "",
            "incident_reference": "",
            "engineering_reference": "compose-smoke",
            "note": "Compose smoke test moved this ticket into active triage.",
        },
    )

    _, body = client.get(f"/tickets/{ticket_id}/")
    csrf = parse_form(body).csrf_token()
    _, body = client.post_form(
        f"/operator/tickets/{ticket_id}/operational-incident/",
        {
            "csrfmiddlewaretoken": csrf,
            "scope": "owned-software",
            "actionability": "auto-fix",
            "access_level": "local-shell",
            "exposure": "private-channel",
            "risk": "medium",
            "p_level": "P3",
            "human_input_required": "no",
            "classification_note": "Generated by the Compose smoke test.",
        },
    )
    if "Operational incident" not in html.unescape(body):
        raise SmokeError("Operational incident creation did not report success.")


def knowledge_base_flow(client: SmokeHttpClient) -> None:
    _, body = client.get("/knowledge-base/")
    if "Android node disconnects during uploads" not in body:
        raise SmokeError("Knowledge base did not render the published demo article.")
    _, body = client.get("/knowledge-base/android-node-upload-disconnects/")
    if "Initial triage steps for node disconnects" not in body:
        raise SmokeError("Knowledge base article detail did not render expected article content.")


def create_api_token(args: argparse.Namespace) -> tuple[str, str]:
    token_name = f"compose-smoke-agent-{uuid.uuid4().hex[:8]}"
    result = compose_exec(
        args,
        "python",
        "manage.py",
        "create_operations_agent_token",
        token_name,
        "--user",
        "operator",
        "--all-scopes",
        print_output=False,
    )
    for line in reversed(result.stdout.splitlines()):
        candidate = line.strip()
        if candidate.startswith("orc_agent_"):
            print(f"Created temporary operations-agent API token {token_name}.")
            return token_name, candidate
    raise SmokeError("Token creation command did not print an operations-agent token.")


def deactivate_api_token(args: argparse.Namespace, token_name: str) -> None:
    compose_exec(
        args,
        "python",
        "manage.py",
        "shell",
        "-c",
        (
            "from tickets.models import OperationsAgentToken; "
            f"OperationsAgentToken.objects.filter(name={token_name!r}).update(is_active=False)"
        ),
        print_output=False,
    )
    print(f"Deactivated temporary operations-agent API token {token_name}.")


def api_flow(client: SmokeHttpClient, token: str) -> int:
    marker = uuid.uuid4().hex[:8]
    ticket_payload = client.post_json(
        "/api/tickets/",
        {
            "title": f"Compose API smoke ticket {marker}",
            "affected_system": "openclaw-runtime",
            "impact": "medium",
            "issue_summary": "Automated operations-agent API smoke test submission.",
            "reproduction_steps": "1. Run scripts/compose_smoke_test.py.\n2. Exercise JSON API flow.",
            "expected_outcome": "The deployed API accepts and tracks the ticket.",
            "actual_outcome": "Smoke test is exercising the operations-agent API path.",
            "additional_context": "Generated by a scoped operations-agent bearer token.",
        },
        token=token,
    )
    ticket_id = ticket_payload["ticket"]["id"]
    client.post_json(
        f"/api/tickets/{ticket_id}/messages/",
        {"body": "Operations-agent API smoke note.", "is_operator_note": True},
        token=token,
    )
    client.post_json(
        f"/api/tickets/{ticket_id}/status/",
        {
            "status": "in_progress",
            "operator": "operator",
            "engineering_reference": "compose-api-smoke",
            "note": "Operations-agent API smoke test moved this ticket into active triage.",
        },
        token=token,
    )
    incident_payload = client.post_json(
        f"/api/tickets/{ticket_id}/operational-incident/",
        {
            "scope": "owned-software",
            "actionability": "auto-fix",
            "access_level": "local-shell",
            "exposure": "private-channel",
            "risk": "medium",
            "p_level": "P3",
            "human_input_required": "no",
            "classification_note": "Generated by the operations-agent API smoke test.",
        },
        token=token,
    )
    detail = client.get_json(f"/api/tickets/{ticket_id}/", token=token)
    if detail["ticket"]["status"] != "in_progress":
        raise SmokeError("API smoke ticket did not reach in_progress status.")
    if not incident_payload["incident"]["reference"].startswith("INC-"):
        raise SmokeError("API incident promotion did not return an incident reference.")
    if not detail["operational_incidents"]:
        raise SmokeError("API ticket detail did not include promoted incident.")
    return ticket_id


def run_smoke(args: argparse.Namespace) -> None:
    args.compose_file = Path(args.compose_file)
    if not args.compose_file.exists():
        raise SmokeError(f"Compose file not found: {args.compose_file}")
    if not Path(args.env_file).exists():
        raise SmokeError(f"Environment file not found: {args.env_file}. Create it from .env.example first.")

    if not args.no_up:
        up_args = ["up", "-d"]
        if args.build:
            up_args.extend(["--build", "--force-recreate"])
        compose(args, *up_args)

    client = SmokeHttpClient(args.base_url.rstrip("/") + "/", args.http_timeout)
    wait_for_app(client, args.ready_timeout)

    compose_exec(args, "python", "manage.py", "migrate", "--noinput")
    compose_exec(args, "python", "manage.py", "seed_demo")

    reporter = SmokeHttpClient(client.base_url, args.http_timeout)
    reporter.login("reporter", "reporter")
    knowledge_base_flow(reporter)
    print("Confirmed published knowledge-base article is visible to reporter.")
    ticket_id = submit_ticket(reporter)
    print(f"Created ticket #{ticket_id}.")

    operator = SmokeHttpClient(client.base_url, args.http_timeout)
    operator.login("operator", "operator")
    operator_flow(operator, ticket_id)
    print(f"Completed operator status update and incident promotion for ticket #{ticket_id}.")

    token_name, api_token = create_api_token(args)
    try:
        api_ticket_id = api_flow(client, api_token)
        print(f"Completed operations-agent API flow for ticket #{api_ticket_id}.")
    finally:
        deactivate_api_token(args, token_name)

    compose_exec(args, "python", "manage.py", "sync_workspace_incidents", "--actor", "operator")
    compose_exec(args, "python", "manage.py", "cleanup_attachments")
    compose_exec(args, "python", "manage.py", "sla_report", "--breached-only")
    compose_exec(args, "python", "manage.py", "check", "--deploy")

    if args.down_after:
        compose(args, "down")
    print("Compose smoke test passed.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the deployed Podman Compose acceptance smoke test for Open Response Center.",
    )
    parser.add_argument("--base-url", default="http://127.0.0.1:8000/")
    parser.add_argument("--compose-file", default="podman-compose.yml")
    parser.add_argument("--env-file", default=".env")
    parser.add_argument("--service", default="web")
    parser.add_argument("--podman", default="podman")
    parser.add_argument("--ready-timeout", type=int, default=120)
    parser.add_argument("--http-timeout", type=int, default=20)
    parser.add_argument("--no-up", action="store_true", help="Use an already-running Compose stack.")
    parser.add_argument("--build", action="store_true", help="Pass --build to podman compose up.")
    parser.add_argument("--down-after", action="store_true", help="Stop the Compose stack after the smoke test.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        run_smoke(args)
    except SmokeError as exc:
        print(f"Smoke test failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
