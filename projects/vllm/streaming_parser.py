#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

from enum import IntEnum
from pathlib import Path
import sys
import types

# Avoid importing unnecessary dependencies
root = Path("/opt/vllm-src/vllm")
for name, directory in (
    ("vllm",               root),
    ("vllm.parser",        root / "parser"),
    ("vllm.parser.engine", root / "parser" / "engine"),
):
    package = types.ModuleType(name)
    package.__path__ = [str(directory)]
    sys.modules.setdefault(name, package)

from vllm.parser.engine.events                  import EventType
from vllm.parser.engine.parser_engine_config    import ParserEngineConfig, ParserState, ToolCallBodyCollection, Transition
from vllm.parser.engine.streaming_parser_engine import StreamingParserEngine


class ParserFormat(IntEnum):
    TOOL_CALL                = 0
    TOOL_CALL_WITH_REASONING = 1
    JSON_ARRAY               = 2
    SEMICOLON_SEQUENCE       = 3


# format (2 bits), token mode (1), literal-first (1), chunk-size index (2), text-holdback index (2)
PARSER_FORMAT_MASK = 0b11
TOKEN_ID_MODE_FLAG = 1 << 2
LITERAL_FIRST_FLAG = 1 << 3
CHUNK_SIZE_SHIFT   = 4
HOLDBACK_SHIFT     = 6
INDEX_MASK         = 0b11

MAX_INPUT_BYTES          = 2049
MAX_REPORTED_TEXT_LENGTH = 300

SPECIAL_TOKEN_ID_BASE = sys.maxunicode + 1

CHUNK_SIZES    = (1, 3, 11, 37)
HOLDBACK_SIZES = (0, 8, 32, 128)


def make_config(parser_format: ParserFormat):
    if parser_format in (ParserFormat.JSON_ARRAY, ParserFormat.SEMICOLON_SEQUENCE):
        terminals = {
            "OPEN":  "<tool_calls>",
            "CLOSE": "</tool_calls>",
        }
        transitions = {
            (ParserState.CONTENT,   "OPEN"):  Transition(ParserState.TOOL_ARGS),
            (ParserState.TOOL_ARGS, "CLOSE"): Transition(ParserState.CONTENT),
        }
        collection = (
            ToolCallBodyCollection.JSON_ARRAY if parser_format == ParserFormat.JSON_ARRAY else
            ToolCallBodyCollection.SEMICOLON_SEQUENCE
        )
    else:
        terminals = {
            "OPEN":  "<tool_call>",
            "CLOSE": "</tool_call>",
        }
        transitions = {
            (ParserState.CONTENT,   "OPEN"):  Transition(ParserState.TOOL_ARGS, (EventType.TOOL_CALL_START,)),
            (ParserState.TOOL_ARGS, "CLOSE"): Transition(ParserState.CONTENT,   (EventType.TOOL_CALL_END,)),
        }
        collection = None

        if parser_format == ParserFormat.TOOL_CALL_WITH_REASONING:
            terminals.update({
                "THINK_START": "<think>",
                "THINK_END":   "</think>",
            })
            transitions.update({
                (ParserState.CONTENT,   "THINK_START"): Transition(ParserState.REASONING, (EventType.REASONING_START,)),
                (ParserState.REASONING, "THINK_END"):   Transition(ParserState.CONTENT,   (EventType.REASONING_END,)),
            })

    return ParserEngineConfig(
        name=f"fuzz_{parser_format.name.lower()}",
        terminals=terminals,
        token_id_terminals=dict(terminals),
        transitions=transitions,
        tool_call_body_collection=collection,
    )


CONFIGS = {parser_format: make_config(parser_format) for parser_format in ParserFormat}


class MockTokenizer:
    def __init__(self, config):
        self.all_special_tokens = sorted(set(config.token_id_terminals.values()), key=len, reverse=True)
        self.all_special_ids    = [SPECIAL_TOKEN_ID_BASE + i for i in range(len(self.all_special_tokens))]

        self.vocab   = dict(zip(self.all_special_tokens, self.all_special_ids))
        self.reverse = dict(zip(self.all_special_ids,    self.all_special_tokens))

    def get_vocab(self):
        return self.vocab

    def decode(self, ids):
        return "".join(self.reverse.get(i, chr(i) if i < SPECIAL_TOKEN_ID_BASE else "") for i in ids)


def tokenize(text, tokenizer, first_marker_literal):
    markers = tokenizer.all_special_tokens
    result  = []
    i = occurrences = 0

    while i < len(text):
        marker = next((m for m in markers if text.startswith(m, i)), None)
        if marker is not None:
            special = (occurrences + first_marker_literal) % 2 == 0
            occurrences += 1
            if special:
                result.append((marker, tokenizer.vocab[marker]))
                i += len(marker)
                continue

        result.append((text[i], ord(text[i])))
        i += 1

    return result


TEXT_EVENTS = {
    EventType.TEXT_CHUNK,
    EventType.REASONING_CHUNK,
    EventType.TOOL_NAME,
    EventType.ARG_VALUE_CHUNK,
}


def normalize(events):
    result = []

    for event in events:
        if event.type in TEXT_EVENTS and not event.value:
            continue

        item = (event.type, event.tool_index, event.value)
        if (result and event.type in TEXT_EVENTS and result[-1][:2] == item[:2]):
            previous   = result[-1]
            result[-1] = (previous[0], previous[1], previous[2] + event.value)
        else:
            result.append(item)

    return result


def parse(config, tokenizer, pieces, chunk_size, holdback):
    engine  = StreamingParserEngine(config, tokenizer=tokenizer)
    events  = []
    pending = ""

    for i in range(0, len(pieces), chunk_size):
        batch = pieces[i:i + chunk_size]
        pending += "".join(text for text, _ in batch)

        release = max(0, len(pending) - holdback)
        delta_text, pending = pending[:release], pending[release:]
        token_ids = ([token_id for _, token_id in batch] if tokenizer is not None else [])

        events.extend(engine.feed(delta_text, token_ids))

    if pending:
        events.extend(engine.feed(pending, []))

    events.extend(engine.finish())
    return normalize(events)


def check_input(data):
    if not 1 < len(data) <= MAX_INPUT_BYTES:
        return

    flags = data[0]
    text  = data[1:].decode("utf-8", "replace")
    if not text:
        return

    parser_format = ParserFormat(flags & PARSER_FORMAT_MASK)
    config = CONFIGS[parser_format]

    use_token_ids        = bool(flags & TOKEN_ID_MODE_FLAG)
    first_marker_literal = bool(flags & LITERAL_FIRST_FLAG)

    chunk_size_index = (flags >> CHUNK_SIZE_SHIFT) & INDEX_MASK
    holdback_index   = (flags >> HOLDBACK_SHIFT)   & INDEX_MASK

    tokenizer = MockTokenizer(config) if use_token_ids else None

    pieces = (
        tokenize(text, tokenizer, first_marker_literal)
        if tokenizer is not None
        else [(ch, 0) for ch in text]
    )

    expected = parse(config, tokenizer, pieces, len(pieces), 0)
    actual   = parse(
        config,
        tokenizer,
        pieces,
        CHUNK_SIZES[chunk_size_index],
        HOLDBACK_SIZES[holdback_index] if use_token_ids else 0,
    )

    if expected != actual:
        raise AssertionError(
            f"Streaming mismatch: flags={flags:#04x}\n"
            f"text={text[:MAX_REPORTED_TEXT_LENGTH]!r}\n"
            f"complete={expected!r}\n"
            f"streamed={actual!r}"
        )


if __name__ == "__main__":
    count = 0
    for path in sorted(Path(sys.argv[1]).iterdir()):
        if path.is_file():
            check_input(path.read_bytes())
            count += 1
    print(f"PASS {count} corpus inputs")

