class AuthenticationFailed(Exception):
    """Raised if the MAC does not verify"""

    pass


class ParserError(Exception):
    """Raised if the header could not be parsed"""

    pass


class UnknownRecipient(Exception):
    """Raised when an unknown recipient line was encountered during header parsing"""

    pass


class NoIdentity(Exception):
    """Raised if no matching identity could be found"""

    pass
