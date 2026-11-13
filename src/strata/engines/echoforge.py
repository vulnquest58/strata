"""Candidate-label generation, ported from echoforge's miner package.

Deterministic parts only for P1: tokenize (ngram.go), n-gram combination
generation (ngram.go GenerateCombinations), and the evolver's templating
methods 2-4 (evolver.go). The Markov generator (methods 1) is deferred:
the original has no seeded RNG, so porting it without injection control
would break reproducibility.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable

# evolver.go:129-136 (prefixes/suffixes), :171-172 (envs/regions)
_PREFIXES = ("api", "dev", "staging", "prod", "internal", "admin", "secure",
             "vpn", "cdn", "app", "web", "portal", "mail", "gateway", "auth",
             "backend", "test")
_SUFFIXES = ("v2", "v3", "eu", "us", "ap", "beta", "new", "prod", "dev", "int")
_ENVS = ("prod", "staging", "dev", "qa", "uat", "sandbox")
_REGIONS = ("eu", "us", "ap", "us-east", "eu-west")
# ngram.go:119-124
_COMBO_SUFFIXES = ("v2", "v3", "eu", "us", "ap", "prod", "dev", "test",
                   "beta", "int", "old", "new")

_TOKEN_SPLIT = re.compile(r"[-_.\s]+")
_SEP = "-"


def tokenize(name: str) -> tuple[str, ...]:
    """Ported from echoforge internal/miner/ngram.go tokenize()."""
    head = name.split(".", 1)[0]
    tokens = []
    for part in _TOKEN_SPLIT.split(head.lower().strip()):
        part = part.strip()
        if len(part) >= 2:
            tokens.append(part)
    return tuple(tokens)


def skip_prefix(token: str) -> bool:
    """Ported from evolver.go skipPrefix()."""
    noise = {"www", "m", "t", "f", "e", "i", "r", "s", "n"}
    return len(token) <= 1 or token in noise


def top_tokens(labels: Iterable[str], top_n: int = 20) -> tuple[str, ...]:
    """Most frequent tokens across confirmed labels (ngram.go TopN analog)."""
    counts: Counter[str] = Counter()
    for label in labels:
        for token in tokenize(label):
            if not skip_prefix(token):
                counts[token] += 1
    return tuple(tok for tok, _ in counts.most_common(top_n))


def token_frequencies(labels: Iterable[str]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for label in labels:
        for token in tokenize(label):
            counts[token] += 1
    return dict(counts)


def generate_ngram_combinations(
    domain: str,
    top_grams: tuple[str, ...],
    industry: tuple[str, ...] = (),
) -> tuple[str, ...]:
    """Ported from ngram.go GenerateCombinations(): singles, cross pairs,
    industry kw pairs, and common suffixes on the top 5 grams."""
    out: list[str] = []
    seen: set[str] = set()

    def add(label: str) -> None:
        candidate = f"{label}.{domain}"
        if label and candidate not in seen:
            seen.add(candidate)
            out.append(candidate)

    for gram in top_grams:
        add(gram)
    for g1 in top_grams:
        for g2 in top_grams:
            if g1 != g2:
                add(f"{g1}{_SEP}{g2}")
        for kw in industry:
            add(f"{g1}{_SEP}{kw}")
            add(f"{kw}{_SEP}{g1}")
    for gram in top_grams[:5]:
        for suffix in _COMBO_SUFFIXES:
            add(f"{gram}{_SEP}{suffix}")
    return tuple(out)


def generate_mutations(
    labels: Iterable[str],
    industry: tuple[str, ...] = (),
    max_per_seed: int = 60,
    domain: str | None = None,
) -> tuple[str, ...]:
    """Ported from evolver.go GenerateEchoes() methods 2-4: prefix/suffix
    templating, industry keyword injection, and env/region combos.

    `labels` are confirmed subdomains (FQDNs); mutations are emitted as
    bare labels when `domain` is None, else as FQDNs under `domain`.
    The per-seed cap counts emitted candidates (echoforge caps echoes, not
    tokens).
    """
    out: list[str] = []
    seen: set[str] = set()

    def add(candidate_label: str, budget: list[int]) -> None:
        if budget[0] <= 0 or not candidate_label or candidate_label in seen:
            return
        seen.add(candidate_label)
        out.append(f"{candidate_label}.{domain}" if domain else candidate_label)
        budget[0] -= 1

    for label in labels:
        budget = [max_per_seed]
        tokens = [t for t in tokenize(label) if not skip_prefix(t)]
        for token in tokens:
            for prefix in _PREFIXES:
                if prefix != token:
                    add(f"{prefix}{_SEP}{token}", budget)
            for suffix in _SUFFIXES:
                add(f"{token}{_SEP}{suffix}", budget)
            for kw in industry:
                add(f"{kw}{_SEP}{token}", budget)
                add(f"{token}{_SEP}{kw}", budget)
            for env in _ENVS:
                add(f"{token}{_SEP}{env}", budget)
            for region in _REGIONS:
                add(f"{token}{_SEP}{region}", budget)
    return tuple(out)
