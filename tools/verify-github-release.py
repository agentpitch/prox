"""Fail-closed release checks; published checks deliberately use no credentials."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


ASSET_NAMES = (
    "pitchProx.exe",
    "pitchProx-windows-amd64.zip",
    "pitchProx-windows-amd64.sha256",
    "pitchProx-build-manifest.json",
)
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
NOT_FOUND = object()


class GateError(Exception):
    pass


def api_json(path, *, authenticated, allow_not_found=False, timeout=5):
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2026-03-10",
        "User-Agent": "pitchProx-updater",
    }
    if authenticated:
        token = os.environ.get("GH_TOKEN")
        if not token:
            raise GateError("GH_TOKEN is required for draft release verification")
        headers["Authorization"] = "Bearer " + token
    request = Request("https://api.github.com/" + path, headers=headers)
    try:
        with urlopen(request, timeout=timeout) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
    except HTTPError as error:
        if error.code == 404 and allow_not_found:
            return NOT_FOUND
        raise GateError(f"GitHub API returned HTTP {error.code} for {path}") from None
    except (URLError, TimeoutError, OSError):
        raise GateError(f"GitHub API request failed for {path}") from None
    if len(body) > MAX_RESPONSE_BYTES:
        raise GateError("GitHub API response exceeded the size limit")
    try:
        return json.loads(body)
    except (ValueError, UnicodeDecodeError):
        raise GateError("GitHub API returned invalid JSON") from None


def preflight(repository, tag):
    release = api_json(
        f"repos/{repository}/releases/tags/{quote(tag, safe='')}",
        authenticated=True,
        allow_not_found=True,
    )
    if release is NOT_FOUND:
        return
    if not isinstance(release, dict) or release.get("tag_name") != tag:
        raise GateError("Release lookup returned unexpected metadata")
    if release.get("draft") is not True:
        raise GateError(f"Release {tag} is already public; refusing to replace published assets")


def local_assets(directory):
    expected = {}
    for name in ASSET_NAMES:
        path = directory / name
        size = path.stat().st_size
        if size <= 0:
            raise GateError(f"Local release asset is empty: {name}")
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        expected[name] = (size, "sha256:" + digest.hexdigest())
    return expected


def verify_assets(assets, expected):
    if not isinstance(assets, list) or len(assets) != len(expected):
        raise GateError("Release must expose exactly the four packaged assets")
    seen = set()
    for asset in assets:
        if not isinstance(asset, dict):
            raise GateError("Release asset metadata is invalid")
        name = asset.get("name")
        if not isinstance(name, str) or name not in expected or name in seen:
            raise GateError("Release asset names are missing, duplicated, or unexpected")
        seen.add(name)
        size, digest = expected[name]
        if asset.get("state") != "uploaded":
            raise GateError(f"Release asset is not fully uploaded: {name}")
        if type(asset.get("size")) is not int or asset["size"] != size:
            raise GateError(f"Release asset size does not match the package: {name}")
        if asset.get("digest") != digest:
            raise GateError(f"Release asset SHA-256 does not match the package: {name}")


def verify_release(release, tag, release_id, *, draft):
    if (
        not isinstance(release, dict)
        or type(release.get("id")) is not int
        or release["id"] != release_id
        or release.get("tag_name") != tag
        or release.get("draft") is not draft
        or release.get("prerelease") is not ("-" in tag)
    ):
        raise GateError("Release ID, tag, publication state, or prerelease state is unexpected")


def prepare_publish(repository, tag, release_id, expected, body_path):
    endpoint = f"repos/{repository}/releases/{release_id}"
    release = api_json(endpoint, authenticated=True)
    verify_release(release, tag, release_id, draft=True)
    assets = api_json(endpoint + "/assets?per_page=100", authenticated=True)
    verify_assets(assets, expected)
    body_path.write_text(json.dumps({"draft": False}) + "\n", encoding="utf-8")


def verify_public(repository, tag, release_id, expected, *, wait_seconds=75):
    deadline = time.monotonic() + wait_seconds
    last_error = "Published release metadata is not available"
    while time.monotonic() < deadline:
        try:
            releases = api_json(
                f"repos/{repository}/releases?per_page=20&page=1",
                authenticated=False,
                timeout=min(5, max(0.1, deadline - time.monotonic())),
            )
            if not isinstance(releases, list):
                raise GateError("Public release list is invalid")
            matching = [item for item in releases if isinstance(item, dict) and item.get("tag_name") == tag]
            if len(matching) != 1:
                raise GateError("Public release list does not contain exactly one matching release")
            verify_release(matching[0], tag, release_id, draft=False)
            verify_assets(matching[0].get("assets"), expected)
            if time.monotonic() >= deadline:
                break
            release = api_json(
                f"repos/{repository}/releases/tags/{quote(tag, safe='')}",
                authenticated=False,
                timeout=min(5, max(0.1, deadline - time.monotonic())),
            )
            verify_release(release, tag, release_id, draft=False)
            verify_assets(release.get("assets"), expected)
            print("Anonymous release list and tag metadata expose all four verified assets")
            return
        except GateError as error:
            last_error = str(error)
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(5, remaining))
    raise GateError("Release is published, but older updater compatibility was not confirmed: " + last_error)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("preflight", "prepare", "published"))
    parser.add_argument("--repository", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--release-id", type=int)
    parser.add_argument("--assets", type=Path, default=Path("release-assets"))
    parser.add_argument("--publish-body", type=Path)
    args = parser.parse_args()
    try:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository):
            raise GateError("Invalid repository name")
        if args.mode == "preflight":
            preflight(args.repository, args.tag)
            print("Release preflight passed")
            return
        if args.release_id is None or args.release_id <= 0:
            raise GateError("A positive numeric release ID is required")
        expected = local_assets(args.assets)
        if args.mode == "prepare":
            if args.publish_body is None:
                raise GateError("--publish-body is required")
            prepare_publish(args.repository, args.tag, args.release_id, expected, args.publish_body)
            print("Draft release assets match the verified local package")
        else:
            verify_public(args.repository, args.tag, args.release_id, expected)
    except (GateError, OSError) as error:
        print(f"Release verification failed: {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
