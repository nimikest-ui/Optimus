"""LLM call #2: Replan on failure with creative divergence."""

import random
import sys
from pathlib import Path
from typing import Optional, List
from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).parent.parent))
from provider import get_provider
from core.tool_retriever import ToolRetriever
from core.planner import ExecutionStep, ExecutionPlan


class ReplanRequest(BaseModel):
    """Request to replan a failed step."""

    step: ExecutionStep
    attempt: int  # 1, 2, 3+
    error_output: str  # stdout/stderr from failed execution
    original_goal: str


class CreativeDivergenceStrategy:
    """Lluminate-based creative reasoning strategies."""

    # Strategies for attempt 3+ (programmatic, no LLM)
    STRATEGIES = {
        "forced_connections": {
            "name": "Forced Connections",
            "prompt_prefix": """You are approaching this problem from a completely different attack phase.
Instead of your current approach, imagine you were in a DIFFERENT MITRE phase entirely.
What tools and techniques would work? Think laterally.""",
            "applicable_when": "Multiple tools from same phase failed",
        },
        "scamper": {
            "name": "SCAMPER Method",
            "prompt_prefix": """Apply SCAMPER to the tool execution:
- Substitute: Different flags or parameters?
- Combine: Pair with another tool?
- Adapt: Modify the approach?
- Modify: Change input format?
- Put to another use: Different context?
- Eliminate: Remove assumptions?
- Reverse: Run opposite direction?""",
            "applicable_when": "Tool found but arguments failing",
        },
        "assumption_reversal": {
            "name": "Assumption Reversal",
            "prompt_prefix": """List every assumption you made about this target.
Now reverse each one. What if:
- The service isn't actually running?
- The tool name is slightly different?
- The output format changed?
- The target responded differently than expected?
What new approach emerges?""",
            "applicable_when": "Expected service/port absent",
        },
        "oblique_strategies": {
            "name": "Oblique Strategies",
            "prompt_prefix": """Take an oblique (sideways) approach:
- If direct attack fails, what's the indirect route?
- What's the weakest link?
- What assumption can you exploit?
- What would a completely different discipline suggest?""",
            "applicable_when": "Stuck, no clear next step",
        },
    }

    @staticmethod
    def select_strategy(failure_context: str, attempt: int) -> str:
        """Select creative divergence strategy for this failure."""
        if attempt < 3:
            return None  # No divergence for attempts 1-2

        # Map failure context to strategy
        if "same phase" in failure_context:
            return "forced_connections"
        elif "argument" in failure_context or "flag" in failure_context:
            return "scamper"
        elif "not found" in failure_context or "no response" in failure_context:
            return "assumption_reversal"
        else:
            return "oblique_strategies"

    @staticmethod
    def get_prompt_injection(strategy: str) -> str:
        """Get the prompt injection for the selected strategy."""
        if strategy in CreativeDivergenceStrategy.STRATEGIES:
            return CreativeDivergenceStrategy.STRATEGIES[strategy]["prompt_prefix"]
        return ""


class Replanner:
    """Replan failed execution steps."""

    def __init__(self):
        self.provider = get_provider()
        self.retriever = ToolRetriever()

    def replan(
        self,
        request: ReplanRequest,
        tool_context: str,
    ) -> Optional[ExecutionStep]:
        """
        Replan a failed step.

        For attempts 1-2: Suggest alternate tool (minimal LLM context)
        For attempt 3+: Inject creative divergence strategy

        Returns new ExecutionStep or None if unable to plan.
        """
        if request.attempt < 3:
            return self._replan_alternate_tool(request, tool_context)
        else:
            return self._replan_with_divergence(request, tool_context)

    def _replan_alternate_tool(
        self, request: ReplanRequest, tool_context: str
    ) -> Optional[ExecutionStep]:
        """Attempts 1-2: Suggest alternate tool."""
        system_prompt = """You are a pentesting automation system replanning a failed step.
A tool failed. Suggest ONE ALTERNATE TOOL from the available context.
Return ONLY: {"tool": "tool_name", "args": "new arguments"}"""

        user_message = f"""Failed step: {request.original_goal}
Tool tried: {request.step.tool}
Error: {request.error_output[:200]}

Available tools:
{tool_context}

Suggest one alternate tool and new arguments."""

        try:
            response = self.provider.create_json_completion(
                prompt=user_message,
                system=system_prompt,
                temperature=0.7,
                max_tokens=500,
            )

            tool = response.get("tool")
            args = response.get("args", "")

            if tool:
                return ExecutionStep(
                    step_num=request.step.step_num,
                    goal=request.step.goal,
                    tool=tool,
                    args=args,
                    success_criteria=request.step.success_criteria,
                    timeout=request.step.timeout,
                )

        except Exception as e:
            print(f"Replanner error: {e}")

        return None

    def _replan_with_divergence(
        self, request: ReplanRequest, tool_context: str
    ) -> Optional[ExecutionStep]:
        """Attempt 3+: Inject creative divergence strategy."""
        # Select strategy based on failure context
        strategy = CreativeDivergenceStrategy.select_strategy(
            request.error_output, request.attempt
        )

        # Get prompt injection for strategy
        divergence_prompt = CreativeDivergenceStrategy.get_prompt_injection(strategy)

        system_prompt = f"""You are a pentesting automation system facing a stuck step.
{divergence_prompt}

Now, suggest ONE tool and new approach from the available context.
Return ONLY: {{"tool": "tool_name", "args": "arguments"}}"""

        user_message = f"""Goal: {request.original_goal}
Failed tool: {request.step.tool}
Attempts: {request.attempt}
Error: {request.error_output[:200]}

Available tools:
{tool_context}

Use the above reasoning to suggest a different approach."""

        try:
            response = self.provider.create_json_completion(
                prompt=user_message,
                system=system_prompt,
                temperature=0.7,  # Creativity, not randomness
                max_tokens=500,
            )

            tool = response.get("tool")
            args = response.get("args", "")

            if tool:
                return ExecutionStep(
                    step_num=request.step.step_num,
                    goal=request.step.goal,
                    tool=tool,
                    args=args,
                    success_criteria=request.step.success_criteria,
                    timeout=request.step.timeout,
                )

        except Exception as e:
            print(f"Replanner with divergence error: {e}")

        return None


def replan_step(
    step: ExecutionStep,
    attempt: int,
    error_output: str,
    original_goal: str,
    tool_context: str,
) -> Optional[ExecutionStep]:
    """Convenience function to replan a step."""
    request = ReplanRequest(
        step=step,
        attempt=attempt,
        error_output=error_output,
        original_goal=original_goal,
    )
    replanner = Replanner()
    return replanner.replan(request, tool_context)
