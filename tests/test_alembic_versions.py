"""Validate the Alembic migration chain without requiring a database."""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory


ALEMBIC_DIR = Path(__file__).resolve().parents[1] / "alembic"


def _load_script_directory() -> ScriptDirectory:
    config = Config()
    config.set_main_option("script_location", str(ALEMBIC_DIR))
    config.set_main_option("version_path_separator", "os")
    return ScriptDirectory.from_config(config)


def test_all_versions_form_single_continuous_chain() -> None:
    """Every migration must be reachable from the head via down_revision links."""
    script = _load_script_directory()
    heads = script.get_heads()

    assert len(heads) == 1, f"expected a single head, got: {heads}"

    head = script.get_revision(heads[0])
    assert head is not None

    visited: set[str] = set()
    current = head
    while current is not None:
        visited.add(current.revision)
        if current.down_revision is None:
            break
        current = script.get_revision(current.down_revision)
        assert current is not None, "broken chain: down_revision points to missing revision"

    all_revisions = list(script.walk_revisions())
    all_revision_ids = {rev.revision for rev in all_revisions}

    assert all_revision_ids == visited, (
        f"migration chain is not continuous. "
        f"orphan revisions: {all_revision_ids - visited}"
    )


def test_no_duplicate_revisions() -> None:
    """Each revision id must appear in exactly one migration file."""
    script = _load_script_directory()
    seen: dict[str, Path] = {}

    for script_file in script.walk_revisions():
        path = Path(script_file.path)
        if script_file.revision in seen:
            pytest.fail(
                f"duplicate revision '{script_file.revision}' in {path} and {seen[script_file.revision]}"
            )
        seen[script_file.revision] = path


def test_down_revisions_are_unique() -> None:
    """A single down_revision must not be referenced by multiple migrations."""
    script = _load_script_directory()
    children: dict[str, list[str]] = {}

    for rev in script.walk_revisions():
        down = rev.down_revision
        if down is not None:
            children.setdefault(down, []).append(rev.revision)

    duplicates = {down: revs for down, revs in children.items() if len(revs) > 1}
    assert not duplicates, f"down_revision referenced by multiple migrations: {duplicates}"


def test_migration_files_are_numbered_sequentially() -> None:
    """File names should use a zero-padded numeric prefix in order."""
    script = _load_script_directory()
    prefixes: list[int] = []

    for rev in script.walk_revisions():
        filename = Path(rev.path).name
        prefix = filename.split("_", 1)[0]
        assert prefix.isdigit(), f"migration filename must start with digits: {filename}"
        prefixes.append(int(prefix))

    prefixes_sorted = sorted(prefixes)
    assert prefixes_sorted == list(range(prefixes_sorted[0], prefixes_sorted[-1] + 1)), (
        f"migration numbering is not sequential: {prefixes_sorted}"
    )
