"""Safe YAML loader that tracks exact 1-indexed file and line metadata."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

PathKey = tuple[str | int, ...]
YAML_EXTENSIONS: frozenset[str] = frozenset({".yaml", ".yml"})


class ManifestLoadError(Exception):
    """Raised when a manifest path cannot be read or contains invalid YAML."""


@dataclass(frozen=True)
class ParsedDocument:
    """A single Kubernetes YAML mapping with source file and line-number index."""

    source: str
    start_line: int
    data: dict[str, Any]
    line_index: dict[PathKey, int] = field(default_factory=dict)

    def location_for(self, path: PathKey = ()) -> str:
        """Return ``source:line`` for ``path``, falling back to nearest ancestor line."""
        current = path
        while current:
            if current in self.line_index:
                return f"{self.source}:{self.line_index[current]}"
            current = current[:-1]
        return f"{self.source}:{self.start_line}"


def _index_node(
    node: yaml.Node,
    prefix: PathKey,
    index: dict[PathKey, int],
    seen: set[int],
) -> None:
    """Recursively record 1-indexed starting lines for mapping keys and sequence items."""
    node_id = id(node)
    if node_id in seen:
        return
    seen.add(node_id)

    index[prefix] = node.start_mark.line + 1

    if isinstance(node, yaml.MappingNode):
        for key_node, value_node in node.value:
            key_str = str(key_node.value)
            child_path = (*prefix, key_str)
            index[child_path] = key_node.start_mark.line + 1
            _index_node(value_node, child_path, index, seen)
    elif isinstance(node, yaml.SequenceNode):
        for idx, item_node in enumerate(node.value):
            child_path = (*prefix, idx)
            _index_node(item_node, child_path, index, seen)


def _expand_list_document(doc: ParsedDocument) -> list[ParsedDocument]:
    """Unwrap Kubernetes ``kind: List`` manifests into individual resource documents."""
    if doc.data.get("kind") != "List":
        return [doc]

    items = doc.data.get("items")
    if not isinstance(items, list):
        return [doc]

    expanded: list[ParsedDocument] = []
    for idx, item in enumerate(items):
        if not isinstance(item, dict):
            loc = doc.location_for(("items", idx))
            raise ManifestLoadError(
                f"{loc}: List item at index {idx} is not a YAML mapping"
            )
        item_prefix: PathKey = ("items", idx)
        item_start = doc.line_index.get(item_prefix, doc.start_line)
        remapped: dict[PathKey, int] = {}
        for path, line in doc.line_index.items():
            if path[:2] == item_prefix:
                remapped[path[2:]] = line
        expanded.append(
            ParsedDocument(
                source=doc.source,
                start_line=item_start,
                data=item,
                line_index=remapped,
            )
        )
    return expanded


def parse_yaml_stream(raw_text: str, *, source: str) -> list[ParsedDocument]:
    """Parse one or more YAML documents safely using ``yaml.SafeLoader`` only."""
    documents: list[ParsedDocument] = []
    loader = yaml.SafeLoader(raw_text)
    try:
        while loader.check_node():
            node = loader.get_node()
            if node is None:
                continue

            # Ignore empty/null documents (e.g., trailing '---' separators).
            if (
                isinstance(node, yaml.ScalarNode)
                and node.tag == "tag:yaml.org,2002:null"
                and node.value == ""
            ):
                continue

            line_num = node.start_mark.line + 1
            if not isinstance(node, yaml.MappingNode):
                raise ManifestLoadError(
                    f"{source}:{line_num}: expected a Kubernetes YAML mapping document, "
                    f"got {type(node).__name__}"
                )

            line_index: dict[PathKey, int] = {}
            _index_node(node, (), line_index, set())

            constructed = loader.construct_document(node)
            if not isinstance(constructed, dict):
                raise ManifestLoadError(
                    f"{source}:{line_num}: expected a Kubernetes YAML mapping document"
                )

            parsed = ParsedDocument(
                source=source,
                start_line=line_num,
                data=constructed,
                line_index=line_index,
            )
            documents.extend(_expand_list_document(parsed))
    except yaml.YAMLError as exc:
        raise ManifestLoadError(f"{source}: invalid YAML syntax: {exc}") from exc
    finally:
        loader.dispose()

    return documents


def load_manifests(
    target: str,
    *,
    stdin_text: str | None = None,
) -> list[ParsedDocument]:
    """Load YAML manifests from a file path, directory, or stdin (``-``)."""
    if target == "-":
        raw = sys.stdin.read() if stdin_text is None else stdin_text
        return parse_yaml_stream(raw, source="<stdin>")

    path = Path(target)
    if not path.exists():
        raise ManifestLoadError(f"Path does not exist: {target}")

    if path.is_file():
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ManifestLoadError(f"Unable to read file '{target}': {exc}") from exc
        return parse_yaml_stream(raw, source=str(path))

    if path.is_dir():
        yaml_files = sorted(
            p for p in path.rglob("*") if p.is_file() and p.suffix.lower() in YAML_EXTENSIONS
        )
        if not yaml_files:
            raise ManifestLoadError(f"No .yaml or .yml files found in directory: {target}")

        documents: list[ParsedDocument] = []
        for yaml_file in yaml_files:
            try:
                raw = yaml_file.read_text(encoding="utf-8")
            except OSError as exc:
                raise ManifestLoadError(f"Unable to read file '{yaml_file}': {exc}") from exc
            documents.extend(parse_yaml_stream(raw, source=str(yaml_file)))
        return documents

    raise ManifestLoadError(f"Unsupported path type: {target}")
