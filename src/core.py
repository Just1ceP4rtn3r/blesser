from statemachine import StateMachine, State


# L2CAP Command Info

SMP_CODE = {
	0x01: "Reject",
	0x02: "Connection Request",
	0x03: "Connection Response",
	0x04: "Configuration Request",
	0x05: "Configuration Response",
	0x06: "Disconnection Request",
	0x07: "Disconnection Response",
	0x08: "Echo Request",
	0x09: "Echo Response",
	0x0A: "Information Request",
	0x0B: "Information Response",
	0x0C: "Create Channel Request",
	0x0D: "Create Channel Response",
	0x0E: "Move Channel Request",
	0x0F: "Move Channel Response",
	0x10: "Move Channel Confirmation Request",
	0x11: "Move Channel Confirmation Response",
	0x12: "Connection Parameter Update Request",
	0x13: "Connection Parameter Update Response",
	0x14: "LE Credit Based Connection Request",
	0x15: "LE Credit Based Connection Response",
	0x16: "Flow Control Credit Ind",
	0x17: "Credit Based Connection Request",
	0x18: "Credit Based Connection Response",
	0x19: "Credit Based Reconfigure Request",
	0x1A: "Credit Based Reconfigure Response",
}