"""Error types and error codes for the JSON signature-boundary audit tool.

Every error carries a machine-readable ``code`` and, when the error is tied to
a position in the input, a byte ``offset`` (offsets are always counted in
bytes, not characters, so they stay meaningful for streamed UTF-8 input).
"""


class AuditError(Exception):
    """Base class for all tool errors.

    Attributes:
        code:    Stable machine-readable error code (see README for the list).
        message: Human-readable description.
        offset:  Byte offset into the input where the error was detected,
                 or None when not position-related.
    """

    def __init__(self, code, message, offset=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.offset = offset

    def to_dict(self):
        d = {"code": self.code, "message": self.message}
        if self.offset is not None:
            d["offset"] = self.offset
        return d


class ParseError(AuditError):
    """Raised while turning raw bytes into a parse tree.

    Codes: E_UTF8, E_SYNTAX, E_UNICODE, E_DEPTH.
    """


class CanonicalError(AuditError):
    """Raised while validating/emitting the safe canonical form.

    Codes: E_DUP_KEY, E_NON_INTEGER, E_RANGE.
    """


class CaseError(AuditError):
    """Raised for bad case definitions or unreadable case inputs.

    Codes: E_SCHEMA, E_IO.
    """
