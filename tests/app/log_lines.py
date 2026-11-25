"""A value a client chose to forge log lines with, and the check that it did not."""

from server.app import log_text

# A line break, a carriage return, an escape character and a long run.
FORGED = "x\nERROR forged line\r\x1b[31m" + "y" * 70_000 + ".json"


def one_line_naming(caplog, logger_name: str, *values: str) -> str:
    """The one record ``logger_name`` wrote: one line, naming each of ``values`` as ``log_text``
    writes it, quoted and cut short, so where it ends shows. Its message."""

    [record] = [record for record in caplog.records if record.name == logger_name]
    message = record.getMessage()
    assert not {"\n", "\r", "\x1b"} & set(message), message[:400]
    assert len(message) < 2_000
    for value in values:
        assert log_text.client_text(value) in message
    return message
