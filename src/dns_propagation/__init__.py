"""Check DNS propagation across public resolvers and lint email authentication records."""

from ._version import __version__
from .check import Expectation, Report, run_check, watch
from .emailauth import check_domain
from .query import DnsQuerier, QueryResult
from .resolvers import BUILTIN, Resolver, Target

__all__ = [
    "BUILTIN",
    "DnsQuerier",
    "Expectation",
    "QueryResult",
    "Report",
    "Resolver",
    "Target",
    "__version__",
    "check_domain",
    "run_check",
    "watch",
]
