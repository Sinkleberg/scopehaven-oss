"""Test-only Python adapter (scopehaven-turn-runner/1) over in-memory app state shaped like the three
templates RT1 ran (stand-ins written for tests, not the templates' code). It uses the shipped shim
(adapters/shim.py) for the channel, the ledger and the snapshot answers, so the tests exercise it.
  conversation.context       an airline context (a dataclass): scalars beside lists. The seat-booking
                             handoff fills in default itinerary values (seat 14C, flight PA441,
                             confirmation IR-D204) before update_seat runs, as the OpenAI
                             customer-service demo's handoff hook does
  airline.reservations       a map of reservations; with --reservations N the whole map is too big
                             for one state message, so only a declared key subset can be read.
                             credit adds to a reservation's credit, so a call delivered twice
                             credits twice (the fault tests' non-idempotent tool)
  tool_spec.current_artifact None until an order is created (a dataclass)
  booking                    a pydantic-shaped model (a stand-in: pydantic is not installed for
                             tests) whose own model_dump leaves out refund_issued, as an excluded
                             field or a custom serializer would; the shim reads its declared fields
  desk                       a dict subclass holding the seat as an item; with desk-attribute it also
                             holds refund_issued as an attribute, which a read of its items would drop
The stub steps drive it as the real adapters' stub models do. A 'parallel' step runs its calls in
threads at once, as frameworks that run tool calls concurrently do; each call goes through the
wrapped tool.
A 'background' step starts its call in a thread and does not wait for it, so the turn ends with
the call still running; the turn-end then reports the unfinished call as a failure (shim.Ledger).
  --misbehave a,b,...  whole-table (answer a key-subset request with the whole map), extra-key (one
                       undeclared entry in a subset answer), bad-remainder (a remainder that is not a
                       digest), set-state (a set in the context), lie-report (an app report that says
                       the seat is 12C), extra-attribute (an attribute set on the context
                       outside its dataclass fields), late-remainder (an entry outside the subset changed just
                       after the AFTER read, with no tool record), desk-attribute (refund_issued as an
                       attribute on the desk dict, beside its items)

usage: python3 -I -B state_adapter.py --template . [--reservations N] [--misbehave a,b]
"""
import argparse
import dataclasses
import json
import os
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "adapters"))
from shim import PROTOCOL, Channel, Ledger, Script, snapshot_values  # noqa: E402


@dataclasses.dataclass
class AirlineContext:
    passenger_name: object = None
    confirmation_number: object = None
    seat_number: object = None
    flight_number: object = None
    account_number: object = "38249175"
    itinerary: list = dataclasses.field(default_factory=list)
    vouchers: list = dataclasses.field(default_factory=list)
    special_service_note: object = None


@dataclasses.dataclass
class Order:
    pizzas: list
    address: str


class FieldInfo:
    def __init__(self, exclude=None):
        self.exclude = exclude


# Stand-in for pydantic's BaseModel, laid out as pydantic v2 lays out a model: declared fields in
# __pydantic_fields__, their values in the instance __dict__, private and extra values beside them.
BaseModel = type("BaseModel", (), {"__module__": "pydantic.main", "__slots__": ("__dict__", "__pydantic_fields_set__", "__pydantic_extra__", "__pydantic_private__"),
                                   "model_dump": lambda self, mode="python": dict(self.__dict__)})


class Booking(BaseModel):
    __pydantic_fields__ = {"seat": FieldInfo(), "refund_issued": FieldInfo()}

    def __init__(self, seat, refund_issued):
        self.__dict__.update(seat=seat, refund_issued=refund_issued)
        self.__pydantic_private__ = self.__pydantic_extra__ = None
        self.__pydantic_fields_set__ = {"seat", "refund_issued"}

    def model_dump(self, mode="python"):
        # The app's own view: refund_issued is left out.
        return {"seat": self.seat}


class Desk(dict):
    pass


class ToolSpec:
    def __init__(self):
        self.current_artifact = None


def reservation(rid, n):
    return {"user_id": f"user_{n % 97}", "flights": [{"flight_number": f"HAT{n % 300:03d}", "date": "2024-05-20"}],
            "payment_history": [{"payment_id": f"credit_card_{n}", "amount": 100 + n % 50}], "cabin": "economy"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--template", required=True)
    ap.add_argument("--reservations", type=int, default=3)
    ap.add_argument("--misbehave", default="")
    a = ap.parse_args()
    misbehave = set(filter(None, a.misbehave.split(",")))
    channel = Channel()
    ledger = script = None
    context, spec, booking = AirlineContext(), ToolSpec(), Booking("14C", False)
    if "set-state" in misbehave:
        context.vouchers = {"V1"}
    if "extra-attribute" in misbehave:
        context.refund_issued = False
    desk = Desk(seat="14C")
    if "desk-attribute" in misbehave:
        desk.refund_issued = False
    reservations = {"J7M7UY": reservation("J7M7UY", 1), "VAAOXJ": reservation("VAAOXJ", 2)}
    for n in range(3, a.reservations + 1):
        reservations[f"R{n:06d}"] = reservation(f"R{n:06d}", n)
    roots = {"conversation": lambda: {"context": context}, "airline": lambda: {"reservations": reservations}, "tool_spec": lambda: spec, "booking": lambda: booking, "desk": lambda: desk}

    def transfer_to_seat_booking():
        # The handoff hook: defaults filled in before the seat agent's own tool runs.
        context.confirmation_number = context.confirmation_number or "IR-D204"
        context.flight_number = context.flight_number or "PA441"
        context.seat_number = context.seat_number or "14C"
        context.passenger_name = context.passenger_name or "Morgan Lee"
        context.itinerary = context.itinerary or [{"flight_number": "PA441", "seat": "14C", "origin": "SFO", "destination": "JFK"}]
        return "Transferred to the seat booking agent."

    def update_seat(confirmation_number, new_seat):
        context.confirmation_number, context.seat_number = confirmation_number, new_seat
        if context.itinerary:
            context.itinerary[0]["seat"] = new_seat
        return f"Updated seat to {new_seat} for confirmation number {confirmation_number}"

    def add_voucher(code):
        context.vouchers.append(code)
        return f"Voucher {code} added."

    def cancel_reservation(reservation_id):
        r = reservations[reservation_id]
        r["status"] = "cancelled"
        r["payment_history"].append({"payment_id": r["payment_history"][0]["payment_id"], "amount": -r["payment_history"][0]["amount"]})
        return f"Reservation {reservation_id} cancelled."

    def change_cabin(reservation_id, cabin):
        reservations[reservation_id]["cabin"] = cabin
        return f"Cabin of {reservation_id} is {cabin}."

    def credit(reservation_id, amount):
        r = reservations[reservation_id]
        r["credit"] = r.get("credit", 0) + amount
        return {"reservation_id": reservation_id, "credit": r["credit"]}

    def book_reservation(reservation_id):
        reservations[reservation_id] = reservation(reservation_id, 7)
        return f"Reservation {reservation_id} booked."

    def create_order(pizza, size, address):
        spec.current_artifact = Order([{"name": pizza, "size": size}], address)
        return "Order created."

    def change_booking(seat, refund):
        booking.__dict__["seat"] = seat
        if refund:
            booking.__dict__["refund_issued"] = True
        return f"Seat {seat}."

    def change_desk(seat, refund):
        desk["seat"] = seat
        if refund:
            desk.refund_issued = True
        return f"Seat {seat}."

    def slow(ms):
        time.sleep(ms / 1000)
        return "slow done"

    def fast():
        return "fast done"

    raw = {f.__name__: f for f in [transfer_to_seat_booking, update_seat, add_voucher, cancel_reservation, change_cabin, credit, book_reservation, create_order, change_booking, change_desk, slow, fast]}
    tools = {}
    entered = threading.Event()

    def entering(fn):
        # Signals once the call is inside the tool body, past the ledger's start of the call.
        def body(*args, **kwargs):
            entered.set()
            return fn(*args, **kwargs)
        return body

    def call(step):
        if step["tool"] in ("parallel", "background"):
            # Calls in threads, each started once the one before is inside its body; each records
            # itself when it ends. 'background' does not wait for them.
            threads = [threading.Thread(target=call_quietly, args=(inner,)) for inner in step["args"]["calls"]]
            for t in threads:
                entered.clear()
                t.start()
                entered.wait(5)
            if step["tool"] == "parallel":
                for t in threads:
                    t.join()
            return
        tools[step["tool"]](**step["args"])

    def call_quietly(step):
        try:
            call(step)
        except Exception:
            pass

    def answer(message):
        paths = message["paths"]
        report = [p for p in paths if p.get("source") == "app-report"]
        own = snapshot_values(roots, [p for p in paths if p.get("source") != "app-report"])
        # The app's own report of its state: what it holds, or (lie-report) a seat it never set.
        for p in report:
            held = snapshot_values(roots, [{**p, "source": "object-path"}])[p["path"]]
            if "lie-report" in misbehave and isinstance(held, dict) and "seat_number" in held:
                held = {**held, "seat_number": "12C"}
            own[p["path"]] = held
        for p in paths:
            value = own[p["path"]]
            if "select" in p and isinstance(value, dict):
                if "whole-table" in misbehave:
                    own[p["path"]] = dict(reservations)
                elif "extra-key" in misbehave:
                    other = next(k for k in sorted(reservations) if k not in p["select"]["keys"])
                    value["entries"][other] = reservations[other]
                elif "bad-remainder" in misbehave:
                    value["remainder"]["digest"] = "unreadable"
        return own

    for message in channel.messages():
        kind = message.get("type")
        if kind == "hello":
            if message.get("protocol") != PROTOCOL:
                channel.send({"type": "error", "message": "protocol"})
                return
            ledger = Ledger(channel, message.get("fault"))
            script = Script(ledger)
            for name, fn in raw.items():
                tools[name] = ledger.wrap(entering(fn), name)
            size = len(json.dumps(reservations, separators=(",", ":")))
            channel.send({"type": "ready", "framework": "fixture-python", "tools": sorted(tools) + ["background", "parallel"],
                          "template": {"reservations": len(reservations), "reservationsJsonBytes": size}, "substitutions": []})
        elif kind == "turn":
            script.start_turn(message["steps"])
            replies = []
            while True:
                step = script.next_step()
                if step is None:
                    break
                if step["kind"] == "text":
                    replies.append(script.render(step["text"]))
                    break
                try:
                    call(step)
                except Exception:
                    pass
            end = {"type": "turn-end", "id": message["id"], "reply": replies[-1] if replies else "", "messages": replies, "stub": script.status()}
            running = ledger.unfinished()
            if running:
                end["failure"] = f"{running} tool call(s) still running at the end of the turn"
            channel.send(end)
        elif kind == "sync":
            channel.send({"type": "sync", "id": message["id"]})
        elif kind == "snapshot":
            try:
                channel.send({"type": "state", "id": message["id"], "values": answer(message)})
                if "late-remainder" in misbehave and message["id"].startswith("after-") and not message["id"].startswith("after-settle-"):
                    # Background work with no tool record, just after the AFTER read: an entry outside the subset moves.
                    threading.Timer(0.02, lambda: reservations.__setitem__("R000003", {**reservations["R000003"], "cabin": "business"})).start()
            except Exception as error:
                channel.send({"type": "error", "message": f"snapshot failed: {type(error).__name__}: {error}"[:3000]})
        elif kind == "close":
            return


if __name__ == "__main__":
    main()
