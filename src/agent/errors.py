"""Central error types."""


class AgentError(Exception):
    pass


class OutOfScopeError(AgentError):
    """Raised when a URL is not explicitly permitted by the rulebook."""


class RateLimitError(AgentError):
    pass


class ProviderError(AgentError):
    pass


class ActionParseError(AgentError):
    pass
