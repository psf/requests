"""
requests.pipeline
~~~~~~~~~~~~~~~~~

This module provides the capabilities for the Requests pipeline system.
"""
import enum
import threading
from collections import defaultdict, OrderedDict
from typing import Callable, Dict, List, Optional, Tuple, Any

from .exceptions import RequestException


class HookStage(enum.Enum):
    """Enum representing the different stages in the request lifecycle."""
    #: Before preparing the request
    BEFORE_PREPARE = 10
    #: After preparing the request but before sending
    AFTER_PREPARE = 15
    #: Before sending the request
    BEFORE_SEND = 20
    #: When an error occurs during sending
    ON_SEND_ERROR = 30
    #: When receiving the response headers
    RESPONSE_HEADERS_RECEIVED = 40
    #: When receiving response body chunks (only for streaming responses)
    RESPONSE_BODY_CHUNK = 50
    #: After receiving the complete response
    RESPONSE_FINALIZED = 60
    #: After executing response hooks
    AFTER_RESPONSE_HOOKS = 70
    #: Before following a redirect
    BEFORE_REDIRECT = 80


class HandlerEntry:
    """Represents a registered handler in the pipeline."""
    __slots__ = ('handler', 'priority', 'stage', 'name')

    def __init__(self, handler: Callable, priority: int, stage: HookStage, name: str):
        self.handler = handler
        self.priority = priority
        self.stage = stage
        self.name = name

    def __lt__(self, other: 'HandlerEntry') -> bool:
        """Compare handlers by priority (lower first)."""
        return self.priority < other.priority

    def __repr__(self) -> str:
        return f"HandlerEntry(name={self.name!r}, priority={self.priority}, stage={self.stage.name!r})"


class PipelineContext:
    """Context object passed to pipeline handlers."""
    __slots__ = (
        'request', 'prepared', 'response', 'exception', 'stage', 'session',
        'adapter', 'kwargs', 'gen', '_state', '_short_circuit_response', '_is_short_circuit'
    )

    def __init__(self,
                 request: Optional['Request'] = None,
                 prepared: Optional['PreparedRequest'] = None,
                 response: Optional['Response'] = None,
                 exception: Optional[Exception] = None,
                 stage: Optional[HookStage] = None,
                 session: Optional['Session'] = None,
                 adapter: Optional['HTTPAdapter'] = None,
                 kwargs: Optional[Dict[str, Any]] = None,
                 gen: Optional[Any] = None):
        self.request = request
        self.prepared = prepared
        self.response = response
        self.exception = exception
        self.stage = stage
        self.session = session
        self.adapter = adapter
        self.kwargs = kwargs or {}
        self.gen = gen
        self._state = {}  # type: Dict[str, Any]
        self._short_circuit_response = None  # type: Optional['Response']
        self._is_short_circuit = False

    @property
    def state(self) -> Dict[str, Any]:
        """Get the state dictionary for this context."""
        return self._state

    def short_circuit(self, response: 'Response') -> None:
        """Short-circuit the pipeline with the given response."""
        self._short_circuit_response = response
        self._is_short_circuit = True
        # Add a marker to the response
        response.is_short_circuit = True

    @property
    def is_short_circuit(self) -> bool:
        """Check if the pipeline has been short-circuited."""
        return self._is_short_circuit

    @property
    def short_circuit_response(self) -> Optional['Response']:
        """Get the short-circuit response if set."""
        return self._short_circuit_response

    def __repr__(self) -> str:
        return (
            f"PipelineContext(stage={self.stage.name!r}, "
            f"is_short_circuit={self._is_short_circuit}, "
            f"has_response={self.response is not None}, "
            f"has_exception={self.exception is not None})"
        )


class PipelineError(RequestException):
    """Base exception for pipeline errors."""
    def __init__(self, message: str, stage: HookStage, handler_name: str):
        super().__init__(message)
        self.stage = stage
        self.handler_name = handler_name

    def __str__(self) -> str:
        return f"{super().__str__()} (stage={self.stage.name}, handler={self.handler_name})"


class PipelineAggregateError(RequestException):
    """Exception that aggregates multiple pipeline errors."""
    def __init__(self, errors: List[PipelineError]):
        super().__init__(f"{len(errors)} pipeline error(s) occurred")
        self.errors = errors

    def __str__(self) -> str:
        return f"{super().__str__()}: {[str(e) for e in self.errors]}"


class PipelineManager:
    """Manages the pipeline of handlers for request lifecycle stages."""
    def __init__(self):
        self._handlers = defaultdict(list)  # type: Dict[HookStage, List[HandlerEntry]]
        self._lock = threading.RLock()

    def register(self,
                 stage: HookStage,
                 handler: Callable,
                 priority: int = 50,
                 name: Optional[str] = None) -> None:
        """
        Register a handler for a specific stage.

        :param stage: The stage to register the handler for.
        :param handler: The handler function to register.
        :param priority: The priority of the handler (lower = executed first).
        :param name: Optional name for the handler (defaults to function name).
        """
        if not callable(handler):
            raise TypeError(f"Handler must be callable, got {type(handler)}")

        handler_name = name or handler.__name__
        entry = HandlerEntry(handler, priority, stage, handler_name)

        with self._lock:
            self._handlers[stage].append(entry)
            # Sort handlers by priority
            self._handlers[stage].sort()

    def unregister(self, stage: HookStage, handler: Callable) -> bool:
        """
        Unregister a handler from a specific stage.

        :param stage: The stage to unregister the handler from.
        :param handler: The handler function to unregister.
        :return: True if the handler was unregistered, False otherwise.
        """
        with self._lock:
            if stage not in self._handlers:
                return False

            handlers = self._handlers[stage]
            for i, entry in enumerate(handlers):
                if entry.handler is handler:
                    del handlers[i]
                    return True
            return False

    def unregister_by_name(self, stage: HookStage, name: str) -> bool:
        """
        Unregister a handler by name from a specific stage.

        :param stage: The stage to unregister the handler from.
        :param name: The name of the handler to unregister.
        :return: True if the handler was unregistered, False otherwise.
        """
        with self._lock:
            if stage not in self._handlers:
                return False

            handlers = self._handlers[stage]
            for i, entry in enumerate(handlers):
                if entry.name == name:
                    del handlers[i]
                    return True
            return False

    def snapshot(self) -> Dict[HookStage, List[HandlerEntry]]:
        """
        Create a snapshot of the current handlers.

        :return: A dictionary mapping stages to lists of handler entries.
        """
        with self._lock:
            return {stage: list(handlers) for stage, handlers in self._handlers.items()}

    def dispatch(self, stage: HookStage, **kwargs) -> PipelineContext:
        """
        Dispatch the handlers for a specific stage.

        :param stage: The stage to dispatch.
        :param kwargs: Additional keyword arguments to pass to the context.
        :return: The context object after processing all handlers.
        """
        context = PipelineContext(stage=stage, **kwargs)
        errors = []

        with self._lock:
            handlers = self._handlers.get(stage, [])
            for entry in handlers:
                try:
                    entry.handler(context)
                    if context.is_short_circuit:
                        break
                except Exception as e:
                    error = PipelineError(f"Handler {entry.name} failed: {e}", stage, entry.name)
                    errors.append(error)

        if errors:
            raise PipelineAggregateError(errors)

        return context


# Global pipeline manager instance
global_pipeline = PipelineManager()