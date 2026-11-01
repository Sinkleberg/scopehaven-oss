# The practice desk's policy (DECISION-EFFECT-01). The engine owns it; the checks never restate it.
#   read_ticket: any known role may read
#   refund:      an agent may refund up to 50; a viewer may not refund
package desk

default allow := false

allow if {
	input.action == "read_ticket"
	data.roles[input.principal]
}

allow if {
	input.action == "refund"
	data.roles[input.principal] == "agent"
	is_number(input.amount)
	input.amount <= 50
}
