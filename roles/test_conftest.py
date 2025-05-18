import pytest
from datetime import datetime
from django.utils import timezone

@pytest.fixture(autouse=True)
def mock_timezone_now(monkeypatch):
    """Mock timezone.now() to return a fixed date for all tests."""
    fixed_now = datetime(2023, 5, 18, 12, 0, tzinfo=timezone.utc)
    
    class MockedDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return fixed_now if tz is None else fixed_now.astimezone(tz)

    monkeypatch.setattr(timezone, 'now', MockedDatetime.now)
