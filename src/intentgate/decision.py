"""S4-WP-22 — the decision this SDK hands back.

Until now this SDK had one shape for every answer: an exception. ``exceptions.py``'s own
header still says it — *"Every gateway response that isn't a clean allow becomes an
exception"* — and that is the defect this package closes.

The readiness report put it in one sentence: **pure exceptions lose the distinction to a
bare** ``except IntentGateError``. A DENY, a STEP_UP, an INDETERMINATE and an unreachable
gateway are four different facts, and a consumer that catches the base class has flattened
them into one. The flattening is invisible until the day somebody needs to treat "the policy
said no" differently from "nobody answered" — and by then every call site has the same
``except``.

    [FROZEN] ODR-R1-018 (TIER_1): "APPROVED — C + NO DEFAULT. Immutable value-returning
    Decision plus opt-in raise_for_permit(). NO ROUTE DEFAULT. UNAVAILABLE remains an
    OUTCOME, never another durable verdict."

So an obtained answer is a VALUE. An exception is reserved for the state in which NO ANSWER
EXISTS — transport failure, an unparseable body, a gateway that could not be reached. And
``raise_for_permit()`` is there for the consumer who wants the raising style: opt-in, at
their call site, with the decision preserved on the exception they get.

THE FOUR VERDICTS AND THE ONE OUTCOME ARE NOT THE SAME KIND OF THING.

    [FROZEN] ODR-R1-004 (TIER_1): "Durable verdicts are exactly PERMIT / DENY / STEP_UP /
    INDETERMINATE. ESCALATE -> INDETERMINATE. RESTRICT and REDACT are OBLIGATIONS, not
    verdicts."

UNAVAILABLE is deliberately absent from the verdict list. It is an OUTCOME: a statement
about the exchange, not about the authority. A fifth verdict would make "we could not ask"
indistinguishable in a ``match`` from "we asked and no verdict could be reached", and those
have opposite remedies — one is retried, the other is not.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from intentgate.exceptions import GatewayError, IntentGateError

#: The contract this SDK speaks. Matches ``answer.CanonicalAnswerVersion`` in the gateway.
CANONICAL_ANSWER_VERSION = "IGA/1"

#: The header an SDK sends to ask for a contract version.
NEGOTIATION_HEADER = "X-IntentGate-Answer-Contract"

VERDICTS: tuple[str, ...] = ("PERMIT", "DENY", "STEP_UP", "INDETERMINATE")
AUTHORITY_KINDS: tuple[str, ...] = ("UNBOUNDED", "BOUNDED")
ASSERTION_CLASSES: tuple[str, ...] = ("CALLER_ASSERTED", "VERIFIED", "DERIVED")

#: One member per rule the gateway enforces, in the gateway's order.
#:
#: Named rather than free text so the shared conformance corpus can assert that this SDK
#: refuses the same case FOR THE SAME REASON as the Go contract, the platform mirror and the
#: TypeScript SDK. Four implementations that reject the same input for different reasons agree
#: by coincidence, and coincidence is not parity.
ANSWER_REFUSALS: tuple[str, ...] = (
    "UNKNOWN_CONTRACT_VERSION",
    "UNKNOWN_VERDICT",
    "MISSING_REASON",
    "MISSING_DECISION_ID",
    "BOUNDS_MISMATCH",
    "AUTHORITY_KIND",
    "MISSING_VALIDITY",
    "PERMIT_WITHOUT_LINEAGE",
    "ABSENCE_ON_A_DECISION",
    "ABSENT_MATERIAL_INCOMPLETE",
    "ABSENT_MATERIAL_LEAK",
    "ASSERTION_CLASS",
)

_INPUT_PATH_MARKER = "input."


def _blank(value: Any) -> bool:
    return not isinstance(value, str) or value.strip() == ""


def _lineage_is_empty(lineage: Mapping[str, Any]) -> bool:
    return all(
        _blank(lineage.get(k))
        for k in ("grant_id", "source_authority_id", "policy_revision", "evidence_ref")
    )


def validate_answer(wire: Mapping[str, Any]) -> str | None:
    """Apply every rule the gateway applies, in its order, returning the FIRST refusal.

    First, because the gateway returns the first error. An SDK that reported a different one
    for an input breaking two rules would disagree with the server about what was wrong, which
    is worse than not checking at all.
    """
    if wire.get("contract_version") != CANONICAL_ANSWER_VERSION:
        return "UNKNOWN_CONTRACT_VERSION"
    if wire.get("verdict") not in VERDICTS:
        return "UNKNOWN_VERDICT"
    if _blank((wire.get("reason") or {}).get("code")):
        return "MISSING_REASON"
    if _blank(wire.get("decision_id")):
        return "MISSING_DECISION_ID"

    authority = wire.get("authority") or {}
    kind = authority.get("kind")
    bounds = authority.get("bounds") or []
    if kind == "BOUNDED":
        if not bounds:
            return "BOUNDS_MISMATCH"
        for bound in bounds:
            if _blank(bound.get("dimension")) or _blank(bound.get("limit")):
                return "BOUNDS_MISMATCH"
    elif kind == "UNBOUNDED":
        if bounds:
            return "BOUNDS_MISMATCH"
    else:
        return "AUTHORITY_KIND"

    validity = wire.get("validity") or {}
    if _blank(validity.get("not_after")) or _blank(validity.get("basis")):
        return "MISSING_VALIDITY"
    if wire.get("verdict") == "PERMIT" and _lineage_is_empty(wire.get("lineage") or {}):
        return "PERMIT_WITHOUT_LINEAGE"

    absent = wire.get("absent") or []
    if wire.get("verdict") != "INDETERMINATE" and absent:
        return "ABSENCE_ON_A_DECISION"
    for material in absent:
        if _blank(material.get("class")) or _blank(material.get("surface")):
            return "ABSENT_MATERIAL_INCOMPLETE"
        if _INPUT_PATH_MARKER in (material.get("name") or ""):
            return "ABSENT_MATERIAL_LEAK"

    for asserted in (wire.get("subject"), wire.get("resource")):
        if asserted is None:
            continue
        if asserted.get("class") not in ASSERTION_CLASSES:
            return "ASSERTION_CLASS"
    return None


class NotPermittedError(IntentGateError):
    """Raised by ``Decision.raise_for_permit()`` on a non-permit. Carries the decision."""

    def __init__(self, decision: Decision) -> None:
        super().__init__(
            f"{decision.verdict}: {decision.reason.get('code', '')}",
            code=0,
            data=decision.reason.get("detail"),
        )
        self.decision = decision


class UnavailableError(GatewayError):
    """Raised when the gateway could not be asked, or answered something unreadable.

    An OUTCOME, not a verdict. It says nothing about the authority, only about the exchange.

        [FROZEN] ODR-R1-018: "NO ROUTE DEFAULT. UNAVAILABLE remains an OUTCOME, never another
        durable verdict."

    ## WHY IT SUBCLASSES ``GatewayError`` RATHER THAN SITTING BESIDE IT

    Measured 2026-09-20: this class was exported and raised NOWHERE, while ``GatewayError`` was
    documented as "Network / transport error reaching the gateway, or an HTTP response that
    isn't well-formed JSON-RPC" — word for word the meaning above. Two classes for one outcome,
    and the raise went to the one the ruling does not name.

    Making this a SUBCLASS is what lets the ruled outcome be raised without breaking a caller
    that catches the older name. ``except GatewayError`` still catches an unavailable exchange;
    ``except UnavailableError`` now distinguishes "no answer exists" from "the gateway answered
    and the answer was an error", which is the distinction ODR-R1-018 exists to preserve.
    """


@dataclass(frozen=True)
class Decision:
    """An immutable decision.

    Frozen, because a mutable decision is one a caller can edit before logging — and the whole
    point of handing back a value instead of raising is that the value is the evidence.
    """

    contract_version: str = ""
    verdict: str = ""
    reason: Mapping[str, Any] = field(default_factory=dict)
    obligations: Sequence[Mapping[str, Any]] = field(default_factory=tuple)
    authority: Mapping[str, Any] = field(default_factory=dict)
    validity: Mapping[str, Any] = field(default_factory=dict)
    decision_id: str = ""
    lineage: Mapping[str, Any] = field(default_factory=dict)
    subject: Mapping[str, Any] | None = None
    resource: Mapping[str, Any] | None = None
    absent: Sequence[Mapping[str, Any]] = field(default_factory=tuple)

    #: Whether the server honoured the contract this SDK asked for.
    #:
    #:     [FROZEN] ODR-R1-053: "An unhonoured IGA/1 negotiation produces an EXPLICIT
    #:     fallback, never a silent one."
    #:
    #: Every legacy gateway route ignores ``X-IntentGate-Answer-Contract`` entirely — measured,
    #: not assumed: ``answer.Negotiate`` has no callers outside its own package. So an SDK that
    #: asked for IGA/1 and received the legacy shape cannot tell whether the server did not
    #: RECOGNISE the version or does not IMPLEMENT negotiation, and the difference matters to
    #: whoever has to fix it. A silent fallback would have been fewer lines and would have
    #: hidden the one fact a consumer needs to act on.
    contract_negotiated: bool = True
    downgrade_reason: str | None = None

    @classmethod
    def from_answer(cls, wire: Mapping[str, Any]) -> Decision:
        """Build from an IGA/1 answer the server honoured."""
        return cls._build(wire, negotiated=True, downgrade_reason=None)

    @classmethod
    def from_downgrade(cls, wire: Mapping[str, Any], reason: str) -> Decision:
        """Build from a shape that is NOT IGA/1, recording the downgrade on the decision.

        The verdict is whatever the legacy body said and is NOT translated into the four-verb
        vocabulary: a legacy ``ALLOW`` is not the same statement as an IGA/1 ``PERMIT``, and
        quietly renaming it would be the silent fallback the ruling forbids in a different
        coat. ``permits()`` on a downgraded decision is therefore false.
        """
        return cls._build(wire, negotiated=False, downgrade_reason=reason)

    @classmethod
    def _build(
        cls, wire: Mapping[str, Any], *, negotiated: bool, downgrade_reason: str | None
    ) -> Decision:
        return cls(
            contract_version=wire.get("contract_version") or "",
            verdict=wire.get("verdict") or "",
            reason=dict(wire.get("reason") or {}),
            obligations=tuple(dict(o) for o in (wire.get("obligations") or ())),
            authority=dict(wire.get("authority") or {}),
            validity=dict(wire.get("validity") or {}),
            decision_id=wire.get("decision_id") or "",
            lineage=dict(wire.get("lineage") or {}),
            subject=dict(wire["subject"]) if wire.get("subject") is not None else None,
            resource=dict(wire["resource"]) if wire.get("resource") is not None else None,
            absent=tuple(dict(m) for m in (wire.get("absent") or ())),
            contract_negotiated=negotiated,
            downgrade_reason=downgrade_reason,
        )

    def to_wire(self) -> dict[str, Any]:
        """The wire shape again, for logging and for the conformance corpus."""
        out: dict[str, Any] = {
            "contract_version": self.contract_version,
            "verdict": self.verdict,
            "reason": dict(self.reason),
            "authority": dict(self.authority),
            "validity": dict(self.validity),
            "decision_id": self.decision_id,
            "lineage": dict(self.lineage),
        }
        if self.obligations:
            out["obligations"] = [dict(o) for o in self.obligations]
        if self.subject is not None:
            out["subject"] = dict(self.subject)
        if self.resource is not None:
            out["resource"] = dict(self.resource)
        if self.absent:
            out["absent"] = [dict(m) for m in self.absent]
        return out

    def refusal(self) -> str | None:
        """The rule this answer breaks, or None. Exposed so a consumer can log WHY."""
        if not self.contract_negotiated:
            return "UNKNOWN_CONTRACT_VERSION"
        return validate_answer(self.to_wire())

    def permits(self) -> bool:
        """ONLY an explicit, valid PERMIT permits.

        It validates rather than reading the verdict field, exactly as the gateway's
        ``Permits()`` does. An answer that says PERMIT and breaks a rule — a permit resting on
        no lineage, say — does not permit, and a consumer reading the field alone would act on
        it.
        """
        return self.refusal() is None and self.verdict == "PERMIT"

    def raise_for_permit(self) -> None:
        """Opt-in raising style (ODR-R1-018's option C).

        The consumer who wants exceptions asks for them, at their call site, and the decision
        rides on the exception so nothing is lost.
        """
        if not self.permits():
            raise NotPermittedError(self)


@dataclass(frozen=True)
class BatchDecision:
    """One entry of a batch result, bound by the caller's own identifier.

    THERE IS NO AGGREGATE HELPER ANYWHERE IN THIS MODULE, AND ITS ABSENCE IS THE POINT.

    S4-WP-06's contract is explicit that an SDK convenience method like ``all_permitted()``
    would reintroduce the aggregate verdict on the client side and "must be explicitly
    forbidden in the SDK acceptance, not merely omitted". So it is forbidden here, and a
    control scans this file's source for the forbidden names rather than trusting that nobody
    adds one.

    A consumer who genuinely wants "did everything pass" writes the reduction themselves, at
    their call site, where collapsing four verdicts into a boolean is visible in their own code
    review instead of hidden behind a helper this SDK blessed.
    """

    entry_id: str
    decision: Decision
