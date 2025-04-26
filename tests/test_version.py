import packaging.version
import pytest

import wintermute


@pytest.mark.parametrize(
    "version,expected_version",
    ((wintermute.__version__, "0.1.0"),),
)
def test_version_matches_expected(version: str, expected_version: str) -> None:
    assert version == expected_version


def test_version_is_valid() -> None:
    packaging.version.parse(wintermute.__version__)
