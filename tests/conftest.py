"""Fixtures partilhadas — mock de HTTP via responses."""

from collections.abc import Iterator

import pytest
import responses as _responses


@pytest.fixture
def mocked_responses() -> Iterator[_responses.RequestsMock]:
    with _responses.RequestsMock() as rsps:
        yield rsps
