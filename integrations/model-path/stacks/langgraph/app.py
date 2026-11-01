"""LangGraph practice subject for MIDTASK-ANY, run with the pinned prototype environment
(langgraph 1.2.11, langchain 1.3.15, langchain-core 1.5.4; see that prototype's
requirements.lock). The agent loop is LangGraph's own (langchain.agents.create_agent:
model node, tool node, routing); this file adds only what the test needs around it: a
loopback HTTP shell, an OpenAI-compatible chat model binding written on langchain-core
(the pinned set has no provider package, and nothing new is installed), the practice
access layer and one write tool.

  python -I -B app.py   (environment: LG_MODEL_BASE_URL, LG_MODEL, LG_PORT, SH_*)

POST /task (user bearer token) authorizes the user when the task starts and runs the
agent to the end; POST /sh-admin/suspend (admin token) suspends the user. The
start-only build never checks again; make-copy.py adds the re-check to the recheck build.
"""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import httpx  # noqa: E402
import sh_access  # noqa: E402
from langchain.agents import create_agent  # noqa: E402
from langchain_core.language_models.chat_models import BaseChatModel  # noqa: E402
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage  # noqa: E402
from langchain_core.outputs import ChatGeneration, ChatResult  # noqa: E402
from langchain_core.runnables import RunnableConfig  # noqa: E402
from langchain_core.tools import tool  # noqa: E402
from langchain_core.utils.function_calling import convert_to_openai_tool  # noqa: E402

BASE_URL, MODEL, PORT = os.environ["LG_MODEL_BASE_URL"], os.environ["LG_MODEL"], int(os.environ.get("LG_PORT", "4497"))


def _openai_message(m):
    if isinstance(m, SystemMessage):
        return {"role": "system", "content": m.content}
    if isinstance(m, HumanMessage):
        return {"role": "user", "content": m.content}
    if isinstance(m, ToolMessage):
        return {"role": "tool", "tool_call_id": m.tool_call_id, "content": str(m.content)}
    if isinstance(m, AIMessage):
        out = {"role": "assistant", "content": m.content or ""}
        if m.tool_calls:
            out["tool_calls"] = [{"id": c["id"], "type": "function", "function": {"name": c["name"], "arguments": json.dumps(c["args"])}} for c in m.tool_calls]
        return out
    raise ValueError(f"unsupported message {type(m).__name__}")


class LoopbackChat(BaseChatModel):
    """An OpenAI-compatible /chat/completions binding (non-streaming)."""
    base_url: str
    model: str
    tools: list = []

    @property
    def _llm_type(self):
        return "loopback-openai-chat"

    def bind_tools(self, tools, **kwargs):
        return self.model_copy(update={"tools": [convert_to_openai_tool(t) for t in tools]})

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        body = {"model": self.model, "messages": [_openai_message(m) for m in messages], "stream": False}
        if self.tools:
            body["tools"] = self.tools
        r = httpx.post(f"{self.base_url}/chat/completions", json=body, timeout=600)
        r.raise_for_status()
        msg = r.json()["choices"][0]["message"]
        calls = [{"name": c["function"]["name"], "args": json.loads(c["function"].get("arguments") or "{}"), "id": c.get("id") or f"call-{i}", "type": "tool_call"} for i, c in enumerate(msg.get("tool_calls") or [])]
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=msg.get("content") or "", tool_calls=calls))])


@tool
def save_note(text: str, config: RunnableConfig) -> str:
    """Save a note to the user's notebook."""
    principal = config["configurable"]["principal"]
    sh_access.audit(principal, "tool.invoked", "notes/new")
    # RECHECK
    with sh_access._connect() as c:
        c.execute("CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT, text TEXT)")
        note_id = c.execute("INSERT INTO notes (owner, text) VALUES (?, ?)", (principal, text[:500])).lastrowid
    sh_access.audit(principal, "note.save", f"notes/{note_id}")
    return f"Saved note {note_id}."


agent = create_agent(LoopbackChat(base_url=BASE_URL, model=MODEL), tools=[save_note],
                     system_prompt="You are a notebook assistant. When the user asks to save a note, call save_note with the note text, then confirm in one sentence.")


class Handler(BaseHTTPRequestHandler):
    def _send(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def _json(self):
        length = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(length) or b"{}") if length <= 65536 else {}

    def do_GET(self):
        self._send(200, {"ok": True}) if self.path == "/health" else self._send(404, {})

    def do_POST(self):
        principal = sh_access.principal_of(self.headers.get("Authorization"))
        if self.path == "/sh-admin/suspend":
            if principal != sh_access.ADMIN:
                return self._send(403, {})
            sh_access.suspend(str(self._json().get("principal", ""))[:80], by=sh_access.ADMIN)
            return self._send(200, {"suspended": True})
        if self.path == "/task":
            if principal != sh_access.USER:
                return self._send(401, {})
            # Authorized when the task starts.
            if sh_access.is_suspended(principal):
                return self._send(403, {})
            text = str(self._json().get("text", ""))[:2000]
            try:
                result = agent.invoke({"messages": [{"role": "user", "content": text}]}, config={"configurable": {"principal": principal}, "recursion_limit": 12})
            except Exception as e:  # the agent failed; the records show whatever it committed
                return self._send(502, {"error": type(e).__name__})
            return self._send(200, {"reply": str(result["messages"][-1].content)[:2000]})
        self._send(404, {})

    def log_message(self, format, *args):
        sys.stderr.write("%s %s\n" % (self.command, self.path))


ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
