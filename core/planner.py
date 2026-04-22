"""LLM call #1: Generate execution plan from prompt and tool context."""

import json
from typing import Optional
from pydantic import BaseModel, Field
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from provider import get_provider


class ExecutionStep(BaseModel):
    """Single execution step in the plan."""

    step_num: int
    goal: str = Field(description="What this step aims to achieve")
    tool: str = Field(description="Tool name to execute")
    args: str = Field(description="Tool arguments (template with {target} placeholders)")
    success_criteria: str = Field(description="How to determine if the step succeeded")
    timeout: int = Field(default=60, description="Timeout in seconds")


class ExecutionPlan(BaseModel):
    """Complete execution plan for a target."""

    target: str
    intent: str
    num_steps: int
    steps: list[ExecutionStep]
    estimated_tokens: int


class Planner:
    """Generates execution plans from prompts via LLM."""

    def __init__(self):
        self.provider = get_provider()

    def plan(
        self,
        user_prompt: str,
        intent: str,
        target: str,
        tool_context: str,
        token_budget: int = 4000,
    ) -> ExecutionPlan:
        """
        Generate an execution plan.

        Args:
            user_prompt: User's request
            intent: Extracted intent (reconnaissance, exploitation, etc.)
            target: Target IP/domain
            tool_context: JSON context of available tools (~800 tokens)
            token_budget: Token budget for this step

        Returns:
            ExecutionPlan with validated steps
        """
        # Build system prompt
        system_prompt = self._build_system_prompt(token_budget)

        # Build user message
        user_message = self._build_user_message(
            user_prompt, intent, target, tool_context
        )

        # Call LLM with JSON schema
        try:
            response_json = self.provider.create_json_completion(
                prompt=user_message,
                system=system_prompt,
                temperature=0.7,
                max_tokens=2000,
            )
        except Exception as e:
            raise RuntimeError(f"Failed to generate plan: {e}")

        # Parse and validate response
        try:
            # Handle nested structure if LLM wraps it in an object
            if "plan" in response_json:
                plan_data = response_json["plan"]
            elif "steps" in response_json:
                plan_data = response_json
            else:
                plan_data = response_json

            # Validate steps
            steps = []
            for i, step_data in enumerate(plan_data.get("steps", [])):
                step = ExecutionStep(
                    step_num=step_data.get("step_num", i + 1),
                    goal=step_data.get("goal", ""),
                    tool=step_data.get("tool", ""),
                    args=step_data.get("args", ""),
                    success_criteria=step_data.get("success_criteria", ""),
                    timeout=step_data.get("timeout", 60),
                )
                steps.append(step)

            # Estimate tokens used
            estimated_tokens = self.provider.estimate_completion_tokens(user_message)

            plan = ExecutionPlan(
                target=target,
                intent=intent,
                num_steps=len(steps),
                steps=steps,
                estimated_tokens=estimated_tokens,
            )

            return plan

        except (KeyError, ValueError) as e:
            raise RuntimeError(f"Failed to parse plan response: {e}\nResponse: {response_json}")

    def _build_system_prompt(self, token_budget: int) -> str:
        """Build system prompt for planning."""
        return f"""You are an expert pentesting automation system.
Your task is to create a structured execution plan for security testing.

IMPORTANT CONSTRAINTS:
1. Generate a valid JSON response with this exact structure:
{{
  "steps": [
    {{
      "step_num": 1,
      "goal": "Description of what this step accomplishes",
      "tool": "tool_name",
      "args": "tool arguments with {{target}} placeholder",
      "success_criteria": "How to detect if step succeeded",
      "timeout": 60
    }}
  ]
}}

2. Respect the token budget of {token_budget} tokens
3. Return ONLY valid JSON, no markdown or explanation
4. Each step should use only ONE tool
5. Keep arguments concise and realistic
6. Steps should be executable sequentially

EXECUTION CONTEXT:
- Tools available are provided in the tool context below
- Always use tools from the provided context
- Timeouts should be realistic for each tool
- Success criteria should be checkable (exit code, output pattern)

Generate a practical, ordered sequence of steps."""

    def _build_user_message(
        self,
        user_prompt: str,
        intent: str,
        target: str,
        tool_context: str,
    ) -> str:
        """Build user message for planner."""
        return f"""User Request: {user_prompt}

TARGET: {target}
INTENT: {intent}

AVAILABLE TOOLS:
{tool_context}

Create a step-by-step execution plan for this target. Return only JSON."""


def plan_from_prompt(
    user_prompt: str,
    intent: str,
    target: str,
    tool_context: str,
    token_budget: int = 4000,
) -> ExecutionPlan:
    """Convenience function to plan directly from components."""
    planner = Planner()
    return planner.plan(user_prompt, intent, target, tool_context, token_budget)
