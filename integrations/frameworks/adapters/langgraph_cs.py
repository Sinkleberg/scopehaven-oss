"""ScopeHaven adapter: LangGraph customer-support tutorial, Part 1 (langchain-ai/langgraph,
docs/docs/tutorials/customer-support/customer-support.ipynb, pinned in the scenario).

Runs the notebook's own code cells from the operator's checkout. The only changes are
declared substitutions, each of which must match exactly once, and each recorded with
the cell's digest before and after:
  faq-local        the FAQ download -> the seeded swiss_faq.md in the working directory
  retriever-local  the OpenAI-embeddings retriever -> a word-overlap retriever (same docs, same k)
  llm-stub         ChatAnthropic -> ScopeHaven's scripted stub model (no model call)
  search-stub      TavilySearchResults -> a stub search tool with one fixed result
and, only with --variant fixed-update (the allowed twin, never upstream code):
  fixed-update     the ticket UPDATE also matches the segment being moved
Tool functions are wrapped where the notebook decorates them (langchain_core.tools.tool),
so the ledger and the fault hook sit at the tool boundary. The SQLite file is read by
ScopeHaven's harness, not by this adapter.

usage: python -I -B langgraph_cs.py --template CHECKOUT --passenger ID [--variant fixed-update]
"""
import argparse
import importlib.metadata as metadata
import json
import os
import re
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from shim import PROTOCOL, Channel, Ledger, Script, sha256_text, sub_once  # noqa: E402

NOTEBOOK = "docs/docs/tutorials/customer-support/customer-support.ipynb"
CELLS = [5, 7, 9, 11, 13, 15, 17, 19, 21, 23]
SEARCH_RESULT = [{"url": "https://weather.example.test/basel-week",
                  "content": "Basel this week: mild, 14 to 18 C, light rain likely on Thursday, sunny at the weekend."}]


class WordOverlapRetriever:
    """Stand-in for the tutorial's embeddings retriever: same documents, same k, no network."""

    def __init__(self, docs):
        self._docs = docs

    def query(self, query, k=5):
        q = set(re.findall(r"[a-z]+", query.lower()))
        scored = []
        for d in self._docs:
            w = set(re.findall(r"[a-z]+", d["page_content"].lower()))
            scored.append((len(q & w) / (1 + len(w) ** 0.5), d))
        scored.sort(key=lambda x: -x[0])
        return [{**d, "similarity": s} for s, d in scored[:k]]


def load(template, variant, ledger, script):
    import langchain_core.tools as lct
    from langchain_core.language_models.chat_models import BaseChatModel
    from langchain_core.messages import AIMessage
    from langchain_core.outputs import ChatGeneration, ChatResult

    class ScriptedChatModel(BaseChatModel):
        """Answers from ScopeHaven's script: a tool call or a text reply per step."""

        @property
        def _llm_type(self):
            return "scopehaven-scripted-stub"

        def bind_tools(self, tools, **kwargs):
            return self

        def _generate(self, messages, stop=None, run_manager=None, **kwargs):
            step = script.next_step()
            if step is None:
                message = AIMessage(content="[scopehaven stub: script exhausted]")
            elif step["kind"] == "tool":
                message = AIMessage(content="", tool_calls=[{"name": step["tool"], "args": step["args"],
                                                             "id": f"call_{script.calls}", "type": "tool_call"}])
            else:
                message = AIMessage(content=script.render(step["text"]))
            return ChatResult(generations=[ChatGeneration(message=message)])

    original = lct.tool

    def wrapped_tool(*args, **kwargs):
        if len(args) == 1 and callable(args[0]) and not kwargs:
            return original(ledger.wrap(args[0]))
        return lambda f: original(*args, **kwargs)(ledger.wrap(f))

    lct.tool = wrapped_tool

    def tavily_search_results_json(query: str) -> list:
        """A search engine optimized for comprehensive, accurate, and trusted results. Useful for when you need to answer questions about current events. Input should be a search query."""
        return [dict(r) for r in SEARCH_RESULT]

    search_stub = original(ledger.wrap(tavily_search_results_json))
    nb_path = os.path.join(template, NOTEBOOK)
    raw = open(nb_path, encoding="utf-8").read()
    nb = json.loads(raw)
    code = {i: "".join(c["source"]) for i, c in enumerate(nb["cells"]) if c["cell_type"] == "code"}
    applied = []
    code[7] = sub_once(code[7], 'response = requests.get(\n    "https://storage.googleapis.com/benchmarks-artifacts/travel-db/swiss_faq.md"\n)\nresponse.raise_for_status()\nfaq_text = response.text',
                       "faq_text = HARNESS_FAQ", "faq-local", applied)
    code[7] = sub_once(code[7], "retriever = VectorStoreRetriever.from_docs(docs, openai.Client())", "retriever = HARNESS_RETRIEVER(docs)", "retriever-local", applied)
    code[21] = sub_once(code[21], 'llm = ChatAnthropic(model="claude-3-sonnet-20240229", temperature=1)', "llm = HARNESS_LLM", "llm-stub", applied)
    code[21] = sub_once(code[21], "TavilySearchResults(max_results=1),", "HARNESS_TAVILY,", "search-stub", applied)
    if variant == "fixed-update":
        code[9] = sub_once(code[9], '"UPDATE ticket_flights SET flight_id = ? WHERE ticket_no = ?",\n        (new_flight_id, ticket_no),',
                           '"UPDATE ticket_flights SET flight_id = ? WHERE ticket_no = ? AND flight_id = ?",\n        (new_flight_id, ticket_no, current_flight[0]),',
                           "fixed-update", applied)
    elif variant is not None:
        raise RuntimeError(f"unknown variant {variant}")
    ns = {"__name__": "langgraph_cs_tutorial", "HARNESS_LLM": ScriptedChatModel(), "HARNESS_TAVILY": search_stub,
          "HARNESS_RETRIEVER": WordOverlapRetriever, "HARNESS_FAQ": open("swiss_faq.md", encoding="utf-8").read()}
    for i in CELLS:
        exec(compile(code[i], f"<cell {i}>", "exec"), ns)
    template_info = {"notebook": NOTEBOOK, "notebookSha256": sha256_text(raw), "cells": CELLS, "variant": variant,
                     "versions": {p: metadata.version(p) for p in ["langgraph", "langchain-core", "langchain-community", "pandas"]}}
    return ns, applied, template_info


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--template", required=True)
    ap.add_argument("--passenger", required=True)
    ap.add_argument("--variant")
    a = ap.parse_args()
    channel = Channel()
    graph = config = ledger = script = None
    for message in channel.messages():
        kind = message.get("type")
        if kind == "hello":
            if message.get("protocol") != PROTOCOL:
                channel.send({"type": "error", "message": "protocol"})
                return
            ledger = Ledger(channel, message.get("fault"))
            script = Script(ledger)
            try:
                ns, applied, info = load(a.template, a.variant, ledger, script)
            except Exception as error:
                channel.send({"type": "error", "message": f"load failed: {type(error).__name__}: {error}"[:3000]})
                return
            graph = ns["part_1_graph"]
            config = {"configurable": {"passenger_id": a.passenger, "thread_id": str(uuid.uuid4())}, "recursion_limit": 40}
            channel.send({"type": "ready", "framework": "langgraph", "tools": [t.name for t in ns["part_1_tools"]],
                          "template": info, "substitutions": applied})
        elif kind == "turn":
            script.start_turn(message["steps"])
            replies, failure = [], None
            try:
                current = graph.get_state(config).values
                n_before = len(current.get("messages", [])) if current else 0
                for _ in graph.stream({"messages": ("user", message["text"])}, config, stream_mode="values"):
                    pass
                for m in graph.get_state(config).values["messages"][n_before:]:
                    if type(m).__name__ == "AIMessage":
                        text = m.content if isinstance(m.content, str) else " ".join(p.get("text", "") for p in m.content if isinstance(p, dict))
                        if text.strip():
                            replies.append(text)
            except Exception as error:
                # The framework raised out of the turn: the user sees an error, and the run is unusable.
                replies.append(f"[run failed visibly: {type(error).__name__}]")
                failure = " ".join(f"{type(error).__name__}: {error}".split())[:400]
            end = {"type": "turn-end", "id": message["id"], "reply": replies[-1] if replies else "",
                   "messages": replies, "stub": script.status()}
            if failure:
                end["failure"] = failure
            channel.send(end)
        elif kind == "sync":
            channel.send({"type": "sync", "id": message["id"]})
        elif kind == "snapshot":
            channel.send({"type": "error", "message": "this adapter has no object paths; its state is the SQLite file"})
        elif kind == "close":
            return


if __name__ == "__main__":
    main()
