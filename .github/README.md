# GitHub Actions - Test Coverage Validation

This repository uses GitHub Actions to ensure that all unit test files referenced in specifications are properly executed during testing.

## Workflows

### 1. `coverage-validation.yml` - Test Coverage Validation
- **Triggers**: Pull requests to main/master branch (when not draft)
- **Purpose**: Ensures all specification unit test paths are executed during pytest
- **Process**:
  1. Runs pytest and captures output
  2. Analyzes specifications in `requirements/specifications/` directory
  3. Validates that all `unit_test` paths are:
     - Valid file paths (files exist)
     - Executed during pytest run
  4. Posts detailed results as PR comments
  5. **Blocks merge** if validation fails

### 2. `traceability-matrix.yml` - Automatic Traceability Matrix Generation
- **Triggers**: 
  - Pull requests merged to main/master branch
  - Direct pushes to main/master branch
- **Purpose**: Automatically generates traceability matrix after successful merges
- **Process**:
  1. Installs cdlreq and dependencies
  2. Generates traceability matrix using `cdlreq export` (Excel format)
  3. Creates fallback JSON/TXT formats if cdlreq unavailable
  4. Commits matrix files back to repository
  5. Posts PR comment with matrix summary
  6. Uploads matrix as workflow artifacts
- **Output Files**:
  - `traceability_matrix.xlsx` - Excel format (preferred)
  - `traceability_matrix.json` - JSON format (fallback)
  - `traceability_matrix.txt` - Human-readable text report (fallback)

### 3. `branch-protection.yml` - Branch Protection Setup
- **Triggers**: Manual workflow dispatch
- **Purpose**: Automatically configure branch protection rules
- **Requirements**: `coverage-summary` status check must pass

## Coverage Validation Details

The workflow validates that:
- ✅ All `unit_test` file paths in specifications exist
- ✅ All referenced unit test files are executed during pytest
- ✅ No specifications have invalid or broken test paths
- ❌ **PRs are blocked** if any issues are found

### Example Specification Format

```yaml
id: SPEC-001
title: Example Specification
description: Example specification for testing
related_requirements:
  - REQ-001
implementation_unit: src/example.py
unit_test: tests/test_example.py  # This file must exist and be executed
```

## Setup Instructions

1. **Automatic Setup**:
   ```bash
   # Trigger the branch protection workflow manually in GitHub Actions
   ```

2. **Manual Setup** (if automatic setup fails):
   - Go to **Settings > Branches** in your repository
   - Add a branch protection rule for `main` (or `master`)
   - Enable these options:
     - ✅ **Require status checks to pass before merging**
     - ✅ **Require branches to be up to date before merging**
     - Required status checks: `coverage-summary`
     - ✅ **Require a pull request before merging**
     - ✅ **Require approvals** (1 reviewer minimum)
     - ✅ **Dismiss stale reviews when new commits are pushed**
     - ✅ **Require conversation resolution before merging**

## Testing Locally

To test coverage validation locally:

```bash
# Run pytest and capture output
python -m pytest tests/ -v > test_output.txt 2>&1

# If cdlreq is available, analyze coverage
cdlreq coverage test_output.txt --directory .

# Expected output shows:
# ✅ Executed tests: (files that were run)
# ❌ Not executed: (files that exist but weren't run)  
# ⚠️ Invalid test files: (files that don't exist)
```

## Common Issues and Solutions

### "Not executed" tests:
1. **Test discovery**: Ensure test files are named `test_*.py` or `*_test.py`
2. **Test functions**: Ensure test functions start with `test_`
3. **Import errors**: Check for syntax errors or missing dependencies
4. **Directory structure**: Verify test files are in correct locations

### "Invalid test files":
1. **Missing files**: Create the test files referenced in specifications
2. **Wrong paths**: Update specification `unit_test` paths to match actual files
3. **Relative paths**: Use correct paths relative to repository root

### Example Fix:
```yaml
# Before (invalid):
unit_test: test_example.py

# After (valid):  
unit_test: tests/test_example.py
```

## Workflow Status

## Workflow Integration

Pull requests **cannot be merged** until:
- ✅ All specification unit test files exist
- ✅ All specification unit test files are executed during pytest
- ✅ Pull request is approved by at least 1 reviewer

After successful merge:
- 📊 **Traceability matrix is automatically generated** using `cdlreq export`
- 📁 **Matrix files are committed** back to the repository
- 💬 **PR comment is posted** with generation summary
- 🏗️ **Artifacts are uploaded** for download

This ensures that:
1. All code referenced in specifications has corresponding unit tests that are actually executed
2. An up-to-date traceability matrix is always available after changes
3. Requirements and specifications relationships are automatically documented
4. Compliance documentation is generated without manual intervention