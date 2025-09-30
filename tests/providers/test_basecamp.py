import pytest

from providers.basecamp import BasecampProvider


@pytest.mark.parametrize(
    "client_id",
    [
        "0123456789abcdef0123456789abcdef",
        "0123456789ABCDEF0123456789ABCDEF",
        "abcdefABCDEF0123456789abcdefABCD",
    ],
)
def test_validate_client_id_accepts_mixed_case_hex(client_id):
    provider = BasecampProvider()
    assert provider.validate_client_id(client_id)


@pytest.mark.parametrize(
    "client_id",
    [
        "",
        "not-a-valid-id",
        "0123456789abcdef0123456789abcdeg",
        "0123456789abcdef0123456789abcde",
        None,
    ],
)
def test_validate_client_id_rejects_invalid_values(client_id):
    provider = BasecampProvider()
    assert not provider.validate_client_id(client_id)  # type: ignore[arg-type]
