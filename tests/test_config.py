from pathlib import Path

from scori.config import ScoriConfig


def test_default_config_no_file(tmp_path: Path) -> None:
    cfg = ScoriConfig.load(tmp_path)
    assert cfg.threshold == 75
    assert cfg.profile == "balanced"
    assert cfg.ignore == []


def test_conservative_profile(tmp_path: Path) -> None:
    (tmp_path / ".scori.toml").write_text('[scori]\nprofile = "conservative"\n')
    cfg = ScoriConfig.load(tmp_path)
    assert cfg.threshold == 50
    assert cfg.profile == "conservative"


def test_aggressive_profile(tmp_path: Path) -> None:
    (tmp_path / ".scori.toml").write_text('[scori]\nprofile = "aggressive"\n')
    cfg = ScoriConfig.load(tmp_path)
    assert cfg.threshold == 90


def test_explicit_threshold_overrides_profile(tmp_path: Path) -> None:
    (tmp_path / ".scori.toml").write_text(
        '[scori]\nprofile = "conservative"\nthreshold = 60\n'
    )
    cfg = ScoriConfig.load(tmp_path)
    assert cfg.threshold == 60
    assert cfg.profile == "conservative"


def test_ignore_list_normalized(tmp_path: Path) -> None:
    (tmp_path / ".scori.toml").write_text(
        '[ignore]\npackages = ["Boto3", "some_lib"]\n'
    )
    cfg = ScoriConfig.load(tmp_path)
    assert "boto3" in cfg.ignore
    assert "some-lib" in cfg.ignore


def test_malformed_toml_returns_defaults(tmp_path: Path) -> None:
    (tmp_path / ".scori.toml").write_text("not valid toml !!!")
    cfg = ScoriConfig.load(tmp_path)
    assert cfg.threshold == 75


def test_unknown_profile_falls_back_to_balanced(tmp_path: Path) -> None:
    (tmp_path / ".scori.toml").write_text('[scori]\nprofile = "ultra"\n')
    cfg = ScoriConfig.load(tmp_path)
    assert cfg.profile == "balanced"
    assert cfg.threshold == 75
