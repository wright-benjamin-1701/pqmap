# Loop-proof fixture (plan 08 acceptance #1)
#
# A Python 3.12 FastAPI app (classical TLS; OpenSSL 3.0/3.3 bundled), deployed
# behind an AWS ALB (the *outermost* TLS terminator). Running `pqmap scan`
# against this tree MUST:
#
#   1. Find an edge `app.py → api.stripe.com` (outbound, HTTPS).
#   2. Resolve the ALB as the outermost TLS owner (plan 05 topology).
#   3. Attach `misleading_code` to the edge (plan 05 "misleading code").
#   4. Score the edge as `Confidentiality=C` (KB has no PQ ALB row; classical
#      only) — *not* inflated by a Python lib bump.
#   5. `pqmap fix` MUST recommend a Rung 3 (IaC) finding — *not* a Rung 1
#      Python dependency bump. Rung 1 is ruled out because the *ALB* is the
#      terminator; a Python `requests` upgrade cannot change what the ALB
#      negotiates.
#
# This is the "loop proof" (plan 08 #1): the remediation targets the correct
# layer (infra), not the code.
