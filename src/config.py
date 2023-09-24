from SMPacket import *
#  TESTPACKET = SMPacket("0104002d100f0f")
                                
smp_pairing_request = SMPacket("0104002d100f0f")
smp_pairing_response = SMPacket("02030009100303")
smp_sent_pairing_public_key = SMPacket(
    "0c3bc363cc118e3c969d59928cba448ed816f4461463ec1e9fd3555deaa8d0ae5409c22f364acd4343b4e6f6df7d025c50970ac67efc2b3541df56b1736401fd3b"
)
smp_rcvd_pairing_public_key = SMPacket(
    "0c37f3e270a8364bfc0dd4c593233f85a9641544aeb101b75ce72c34d5479ee15ddcfc8758259a8aac630864d49f54ca4b1b8d9c1a5726dab7a8a515984ab79647"
)
smp_rcvd_pairing_confirm = SMPacket("0342ff15797f80e582295214eb8fc593a0")
smp_sent_pairing_random = SMPacket("0405c8c1f664d6cb64a72ffaf73a74bb16")
smp_rcvd_pairing_random = SMPacket("04193bfe84108e302c08cbfcb054023648")
smp_sent_DHKey_check = SMPacket("0d94489b02ab4206c6a5edd458f9729d83")
smp_rcvd_DHKey_check = SMPacket("0d7e8f9165180d5a11cc043cd48adc5c83")