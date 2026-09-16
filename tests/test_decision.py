"""S4-WP-22 :: the SDK speaks the same contract as the gateway, proven against the same bytes.

The corpus is emitted by ``gateway/internal/answer``'s own test and carried into this
repository verbatim. The platform mirror and the TypeScript SDK replay it too. **Four
runtimes, one artifact, one digest** — and each case names the REFUSAL, because four
implementations that reject the same input for different reasons agree by coincidence.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from intentgate.decision import (
    ANSWER_REFUSALS,
    CANONICAL_ANSWER_VERSION,
    VERDICTS,
    Decision,
    NotPermittedError,
    validate_answer,
)
from intentgate.exceptions import IntentGateError

HERE = Path(__file__).parent
CORPUS_PATH = HERE / "testdata" / "iga1-conformance-corpus.json"
RAW = CORPUS_PATH.read_bytes()
CORPUS = json.loads(RAW)

#: sha256 of the corpus. The gateway pins it in ``answer.CorpusDigest``; the platform mirror
#: and the TypeScript SDK pin the same value.
CORPUS_DIGEST = "5c1c2de450fa27a50947712c81558fdc3644ed6da992a01b77576022b69ac795"


def case(name: str) -> dict:
    return next(c for c in CORPUS["cases"] if c["name"] == name)["answer"]


class TestTheCorpusIsTheOneEveryRuntimeReads:
    def test_is_the_exact_bytes_the_gateway_emitted(self) -> None:
        assert hashlib.sha256(RAW).hexdigest() == CORPUS_DIGEST

    def test_declares_the_contract_it_is_about(self) -> None:
        assert CORPUS["artifact"] == "intentgate-iga1-conformance-corpus"
        assert CORPUS["contract_version"] == CANONICAL_ANSWER_VERSION

    def test_exercises_every_refusal(self) -> None:
        # Non-vacuity. A corpus of valid answers passes against an SDK that never refuses
        # anything, and a rule exercised zero times is a rule this runtime is not held to.
        seen = {c["expect"] for c in CORPUS["cases"]}
        assert "VALID" in seen
        for refusal in ANSWER_REFUSALS:
            assert refusal in seen, refusal


@pytest.mark.parametrize("entry", CORPUS["cases"], ids=lambda e: e["name"])
def test_every_case_agrees_with_the_gateway_and_for_the_same_reason(entry: dict) -> None:
    expected = None if entry["expect"] == "VALID" else entry["expect"]
    assert validate_answer(entry["answer"]) == expected


class TestAnObtainedAnswerIsAValue:
    """The defect this closes: with exceptions only, a DENY, a STEP_UP and an INDETERMINATE
    all arrive at the same ``except IntentGateError`` and the caller has flattened three
    different facts into one."""

    @pytest.mark.parametrize(
        ("name", "verdict"),
        [
            ("valid_permit_unbounded", "PERMIT"),
            ("valid_deny", "DENY"),
            ("valid_step_up", "STEP_UP"),
            ("valid_indeterminate_without_absent", "INDETERMINATE"),
        ],
    )
    def test_returns_a_decision_for_every_verdict(self, name: str, verdict: str) -> None:
        decision = Decision.from_answer(case(name))
        assert decision.verdict == verdict
        assert decision.decision_id

    def test_only_an_explicit_valid_permit_permits(self) -> None:
        assert Decision.from_answer(case("valid_permit_unbounded")).permits() is True
        assert Decision.from_answer(case("valid_deny")).permits() is False
        assert Decision.from_answer(case("valid_step_up")).permits() is False

        # permits() VALIDATES rather than reading the field. An answer that says PERMIT and
        # rests on no lineage does not permit, and a consumer reading the field would act on it.
        bad = Decision.from_answer(case("permit_without_lineage"))
        assert bad.verdict == "PERMIT"
        assert bad.permits() is False
        assert bad.refusal() == "PERMIT_WITHOUT_LINEAGE"

    def test_is_immutable_because_the_value_is_the_evidence(self) -> None:
        decision = Decision.from_answer(case("valid_permit_unbounded"))
        with pytest.raises(FrozenInstanceError):
            decision.verdict = "PERMIT"  # type: ignore[misc]

    def test_raise_for_permit_is_opt_in_and_carries_the_decision(self) -> None:
        Decision.from_answer(case("valid_permit_unbounded")).raise_for_permit()  # no raise

        with pytest.raises(NotPermittedError) as caught:
            Decision.from_answer(case("valid_deny")).raise_for_permit()
        # ODR-R1-018 option C: the consumer who wants exceptions asks for them at their call
        # site, and nothing is lost when they do.
        assert isinstance(caught.value, IntentGateError)
        assert caught.value.decision.verdict == "DENY"
        assert caught.value.decision.reason["code"] == "NO_GRANT"


class TestUnavailableIsAnOutcomeNotAFifthVerdict:
    def test_the_vocabulary_has_exactly_four_members(self) -> None:
        #   [FROZEN] ODR-R1-018: "UNAVAILABLE remains an OUTCOME, never another durable
        #   verdict."
        #
        # A fifth verdict would make "we could not ask" indistinguishable in a match from "we
        # asked and no verdict could be reached", and those have opposite remedies.
        assert VERDICTS == ("PERMIT", "DENY", "STEP_UP", "INDETERMINATE")
        assert "UNAVAILABLE" not in VERDICTS


class TestAnUnhonouredNegotiationIsExplicit:
    def test_records_the_downgrade_on_the_decision_itself(self) -> None:
        #   [FROZEN] ODR-R1-053: "An unhonoured IGA/1 negotiation produces an EXPLICIT
        #   fallback, never a silent one."
        legacy = {"decision": "ALLOW", "record": {"decision_id": "DEC-1"}}
        decision = Decision.from_downgrade(
            legacy, "server returned the legacy {decision, record} shape"
        )
        assert decision.contract_negotiated is False
        assert "legacy" in (decision.downgrade_reason or "")

    def test_a_downgraded_decision_never_permits(self) -> None:
        # A legacy ALLOW is not the same statement as an IGA/1 PERMIT, and renaming it would be
        # the silent fallback in a different coat.
        decision = Decision.from_downgrade(
            {"verdict": "ALLOW", "decision_id": "DEC-1"}, "legacy shape"
        )
        assert decision.permits() is False
        assert decision.refusal() == "UNKNOWN_CONTRACT_VERSION"


class TestThereIsNoAggregateHelper:
    """S4-WP-06's contract: such a helper "would reintroduce the aggregate verdict on the
    client side and must be explicitly forbidden in the SDK acceptance, not merely omitted"."""

    SOURCE = (Path(__file__).parent.parent / "src" / "intentgate" / "decision.py").read_text()
    # Docstrings and comments stripped first: this module's own prose names the forbidden
    # helpers, and a scan that reads prose finds the very word it is looking for.
    CODE = re.sub(r'"""[\s\S]*?"""', " ", SOURCE)
    CODE = re.sub(r"(?m)^\s*#.*$", " ", CODE)

    def test_reads_real_source(self) -> None:
        # Non-vacuity: a scan that read nothing reports no findings and looks identical to one
        # that read everything and found none.
        assert "class Decision" in self.CODE
        assert len(self.CODE) > 1000

    @pytest.mark.parametrize(
        "forbidden", ["all_permitted", "any_denied", "worst_verdict", "permit_count", "summary"]
    )
    def test_declares_no_aggregate(self, forbidden: str) -> None:
        assert forbidden not in self.CODE


class TestTheRouteHasNoDefault:
    """[FROZEN] ODR-R1-018: "NO ROUTE DEFAULT."

    ``/v1/mcp`` runs the legacy capability/bundle pipeline; ``/v1/mcp/ig`` is governed solely
    by the BA-/IG- chain. They are different authorities. A default would move every consumer
    from one to the other on an upgrade and none of them would read a changelog entry about it.
    """

    def test_refuses_to_construct_without_a_route(self) -> None:
        from intentgate.client import (
            ROUTE_MCP_GOVERNED,
            ROUTE_MCP_LEGACY,
            Gateway,
            RouteNotChosenError,
        )

        with pytest.raises(TypeError):
            Gateway("http://gw.example")  # type: ignore[call-arg]

        with pytest.raises(RouteNotChosenError) as caught:
            Gateway("http://gw.example", route="   ")
        # The message names both routes: an error that says "required" and stops there sends
        # the reader to the source to find out what the options were.
        assert ROUTE_MCP_GOVERNED in str(caught.value)
        assert ROUTE_MCP_LEGACY in str(caught.value)


class TestTheIndeterminateStimulusIsProducedDeliberately:
    """[FROZEN] ODR-R1-053: "The indeterminate stimulus is produced deliberately, since no
    route has ever emitted one." (S4-WP-22-D3, option A)

    ``wellformed.Enumeration.Indeterminate()`` has zero callers outside its package. So this
    proves the SDK's HANDLING of an INDETERMINATE and nothing about the gateway's ability to
    produce one — and saying which of the two was proven is the whole reason the ruling chose a
    fixture over a staged Lab stimulus.
    """

    def test_an_indeterminate_is_an_answer_not_an_absence(self) -> None:
        decision = Decision.from_answer(case("valid_indeterminate_with_absent"))
        assert decision.verdict == "INDETERMINATE"
        assert decision.permits() is False
        assert decision.refusal() is None  # a VALID answer that simply is not a permit
        assert len(decision.absent) == 1
        assert decision.absent[0]["surface"] == "authorize"

        # The distinction the package exists for: an INDETERMINATE is an ANSWER. It is not the
        # same as no answer, which is what UnavailableError means.
        with pytest.raises(NotPermittedError):
            decision.raise_for_permit()
