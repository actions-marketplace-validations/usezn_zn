"""
Example: Integrating zn-gate with LangChain / LangGraph.
Zero external dependencies required by zn-gate.
"""
from zn_gate.integrations import ZnGuardCallbackHandler

# Attach handler to any LangChain agent, chain, or LLM call
handler = ZnGuardCallbackHandler(
    on_block="raise",     # Raise GuardBlockError on injection attempts
    mask_secrets=True,    # Automatically mask leaked credentials (AWS, OpenAI, GitHub tokens)
)

print("ZnGuardCallbackHandler initialized and ready for LangChain agent loops.")
