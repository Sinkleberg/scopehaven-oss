# Payment witness provenance

Each original payment window includes `witnessSource`: `observer-dispatched` when the double sends its own witness, `external` for delivery outside that helper, or `none` when no witness is configured. An earlier request marker cannot replace observer provenance. `external` describes dispatch origin; it does not authenticate the sender.

An observer witness can complete recorder capture even when the application never contacts the double. `evaluateRefundCount` therefore returns inconclusive for every observer dispatched window, including expected zero. It accepts no closure flag and cannot validate an independent source by itself. Existing coverage and custody checks still apply to other windows.

The temporal refund collector may use such a window only with its separately validated live application closure. This is a local synthetic fixture contract, not proof of arbitrary application isolation or real provider settlement.
