"""LangGraph adapter — wraps ToolNode with frenum evaluation."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from frenum._types import Decision, ToolCall
from frenum.engine import Engine

if TYPE_CHECKING:
    from langgraph.prebuilt import ToolNode


def guarded_tool_node(
    tool_node: ToolNode,
    engine: Engine,
) -> Any:
    """Wrap a LangGraph ToolNode with frenum pre-evaluation.

    Returns a function with the same signature as ToolNode.__call__,
    suitable for use as a node in a StateGraph.

    Blocked tool calls return ToolMessage with the block reason.
    Allowed calls pass through to the real ToolNode.
    If an AIMessage has multiple tool calls, each is evaluated
    independently — blocked calls don't prevent allowed ones.

    Usage::

        from langgraph.prebuilt import ToolNode
        from frenum import Engine
        from frenum.adapters.langgraph import guarded_tool_node

        tools = [search, calculator]
        engine = Engine.from_yaml("frenum.yaml")
        safe_tools = guarded_tool_node(ToolNode(tools), engine)

        builder.add_node("tools", safe_tools)
    """

    def _guarded(state: dict[str, Any]) -> dict[str, Any]:
        from langchain_core.messages import AIMessage, ToolMessage

        messages = state.get("messages", [])
        last = messages[-1] if messages else None

        if not isinstance(last, AIMessage) or not last.tool_calls:
            return tool_node.invoke(state)

        blocked_messages: list[ToolMessage] = []
        allowed_calls = []

        for tc in last.tool_calls:
            call = ToolCall(
                name=tc["name"],
                args=tc.get("args", {}),
                call_id=tc.get("id", ""),
                user_id=state.get("user_id", ""),
            )
            result = engine.evaluate(call)

            if result.decision == Decision.BLOCK:
                blocked_messages.append(
                    ToolMessage(
                        content=(
                            f"[BLOCKED by {result.blocking_rule.rule_name}]: "
                            f"{result.reason}"
                            if result.blocking_rule
                            else "[BLOCKED]"
                        ),
                        tool_call_id=tc.get("id", ""),
                        name=tc["name"],
                    )
                )
            else:
                allowed_calls.append(tc)

        if not allowed_calls:
            return {"messages": blocked_messages}

        # Reconstruct state with only allowed calls
        filtered_message = AIMessage(
            content=last.content,
            tool_calls=allowed_calls,
        )
        filtered_state = {**state, "messages": [*messages[:-1], filtered_message]}

        result_state = tool_node.invoke(filtered_state)
        result_state["messages"] = blocked_messages + result_state.get("messages", [])
        return result_state

    return _guarded
