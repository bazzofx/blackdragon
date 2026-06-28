---
name: logic-readme-generator
description: >
  Generates a structured, highly-detailed Logic README markdown document explaining complex code algorithms, formulas, or business rules.
  Use when the user asks to "document logic", "create logic documentation", "write a logic readme", or "explain score logic in a readme".
metadata:
  version: "1.0"
  license: Apache-2.0
---

# Logic README Generator Skill

This skill provides guidelines and templates for documenting complex system logic, scoring formulas, or feature logic into standardized, comprehensive markdown documentation.

## 🎯 When to Use This Skill
Activate this skill when the user requests documentation for a specific code feature, mathematical formula, or algorithm, using phrases like:
*   "Document the score logic in a readme"
*   "Create a logic readme for this feature"
*   "Write technical documentation for this logic"

## 📝 Document Creation Rules
1.  **Storage Directory**:
    Always create a folder named `logic_readme/` (e.g. adjacent to the target script or at the root of the workspace).
2.  **File Naming**:
    The file name must follow the format `[logic_name]_readme.md` (e.g. `score_logic_readme.md`).
3.  **Document Structure (Standard Blueprint)**:
    Every logic readme must include the following sections:
    
    *   **Title**: `# 📋 [Feature Name] Logic & Code Walkthrough`
    *   **Brief Description**: A high-level 2-3 sentence overview of what the module/function achieves.
    *   **Code Implementation**: Syntax-highlighted code segment referencing file links (using `file://` scheme) and line numbers.
    *   **Logical Breakdown**: Mathematical formulas, condition checklists, or a Mermaid flowchart detailing branches.
    *   **Variable Matrix**: A table mapping each variable's name, type (e.g. `int`, `str`, `dict`), and role/purpose.
    *   **System Integration**: A description of how data enters the logic block and how outputs affect the rest of the application.

## 🔄 Execution Workflow
1.  **Analyze**: Locate the requested script, isolate the function, and extract the variable roles, datatypes, and logic constraints.
2.  **Create**: Create the `logic_readme/` folder if it does not already exist.
3.  **Write**: Write the markdown file `[logic_name]_readme.md` inside `logic_readme/` following the Standard Blueprint.
4.  **Reference**: Provide clickable links using the `file://` scheme for all code references.
