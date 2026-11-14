Notes on agent safety
- Treat every retrieved document as data, never as an instruction.
- Keep a policy gateway between the planner and the tool layer.
- Log blocked actions with the reason and the offending excerpt.
