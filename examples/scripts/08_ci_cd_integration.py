#!/usr/bin/env python3
"""
PolicyBind Example: CI/CD Integration

This script demonstrates how to integrate PolicyBind into CI/CD pipelines,
including:

1. Policy validation in CI pipelines
2. Policy testing with test fixtures
3. Pre-deployment compliance checks
4. Automated policy deployment
5. Integration with GitHub Actions, GitLab CI, and Jenkins
6. Policy drift detection
7. Rollback procedures

This example shows patterns that can be adapted for any CI/CD system.

Prerequisites:
    - PolicyBind installed: pip install policybind

Usage:
    python 08_ci_cd_integration.py
"""

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


def main() -> int:
    """
    Main function demonstrating CI/CD integration.

    Returns:
        Exit code (0 for success, 1 for errors).
    """
    print("=" * 60)
    print("PolicyBind Example: CI/CD Integration")
    print("=" * 60)
    print()

    # -------------------------------------------------------------------------
    # Step 1: CLI Overview for CI/CD
    # -------------------------------------------------------------------------
    print("Step 1: PolicyBind CLI for CI/CD...")
    print("-" * 60)

    cli_commands = {
        "Policy Management": [
            ("policybind policy validate PATH", "Validate policy syntax"),
            ("policybind policy load PATH --dry-run", "Validate without applying"),
            ("policybind policy test PATH --request JSON", "Test policy against request"),
            ("policybind policy diff VERSION1 VERSION2", "Compare policy versions"),
            ("policybind policy rollback VERSION", "Rollback to previous version"),
        ],
        "Registry Management": [
            ("policybind registry list", "List all deployments"),
            ("policybind registry check-compliance ID", "Check deployment compliance"),
            ("policybind registry export", "Export registry data"),
        ],
        "Token Management": [
            ("policybind tokens list", "List all tokens"),
            ("policybind tokens validate TOKEN", "Validate a token"),
        ],
        "Audit and Reporting": [
            ("policybind audit stats", "Get enforcement statistics"),
            ("policybind audit export --format json", "Export audit logs"),
        ],
        "Configuration": [
            ("policybind config show", "Show current configuration"),
            ("policybind config validate", "Validate configuration"),
            ("policybind init", "Initialize PolicyBind in a project"),
        ],
    }

    print("\nCLI Commands for CI/CD Integration:")
    for category, commands in cli_commands.items():
        print(f"\n  {category}:")
        for cmd, description in commands:
            print(f"    {cmd}")
            print(f"      -> {description}")

    print()

    # -------------------------------------------------------------------------
    # Step 2: Policy Validation Script
    # -------------------------------------------------------------------------
    print("Step 2: Policy Validation Script...")
    print("-" * 60)

    validation_script = '''#!/bin/bash
# ci/validate-policies.sh
# Validates all policy files in the repository

set -e

echo "=== PolicyBind Policy Validation ==="

# Find all policy files
POLICY_FILES=$(find policies/ -name "*.yaml" -o -name "*.yml")

ERRORS=0

for file in $POLICY_FILES; do
    echo "Validating: $file"
    if policybind policy validate "$file" --quiet; then
        echo "  OK"
    else
        echo "  FAILED"
        ERRORS=$((ERRORS + 1))
    fi
done

if [ $ERRORS -gt 0 ]; then
    echo ""
    echo "Validation failed: $ERRORS errors found"
    exit 1
fi

echo ""
echo "All policies validated successfully!"
exit 0
'''

    print("\nPolicy Validation Script (ci/validate-policies.sh):")
    print(validation_script)

    print()

    # -------------------------------------------------------------------------
    # Step 3: Policy Testing Framework
    # -------------------------------------------------------------------------
    print("Step 3: Policy Testing Framework...")
    print("-" * 60)

    test_fixtures = '''# tests/policy_fixtures.yaml
# Test fixtures for policy testing

test_cases:
  # Test 1: Engineering should be allowed GPT-4
  - name: "Engineering can access GPT-4"
    request:
      provider: openai
      model: gpt-4
      user_id: eng-user-001
      department: engineering
      use_case: code-review
    expected:
      decision: ALLOW

  # Test 2: Marketing should be denied GPT-4
  - name: "Marketing cannot access GPT-4"
    request:
      provider: openai
      model: gpt-4
      user_id: mkt-user-001
      department: marketing
      use_case: content-generation
    expected:
      decision: DENY

  # Test 3: PII data should require audit
  - name: "PII requests are audited"
    request:
      provider: openai
      model: gpt-3.5-turbo
      user_id: hr-user-001
      department: hr
      data_classification: pii
    expected:
      decision: AUDIT

  # Test 4: High-risk models require approval
  - name: "High-risk models blocked without approval"
    request:
      provider: openai
      model: gpt-4-vision-preview
      user_id: eng-user-001
      department: engineering
      vision_approved: false
    expected:
      decision: DENY
'''

    print("\nTest Fixtures (tests/policy_fixtures.yaml):")
    print(test_fixtures)

    test_runner = '''#!/bin/bash
# ci/test-policies.sh
# Runs policy tests against fixtures

set -e

echo "=== PolicyBind Policy Tests ==="

POLICY_PATH="${POLICY_PATH:-policies/}"
FIXTURES="${FIXTURES:-tests/policy_fixtures.yaml}"

# Run policy tests
policybind policy test "$POLICY_PATH" \\
    --fixtures "$FIXTURES" \\
    --format junit \\
    --output test-results/policy-tests.xml

# Check exit code
if [ $? -eq 0 ]; then
    echo "All policy tests passed!"
else
    echo "Policy tests failed!"
    exit 1
fi
'''

    print("\nPolicy Test Runner (ci/test-policies.sh):")
    print(test_runner)

    print()

    # -------------------------------------------------------------------------
    # Step 4: GitHub Actions Workflow
    # -------------------------------------------------------------------------
    print("Step 4: GitHub Actions Integration...")
    print("-" * 60)

    github_workflow = '''# .github/workflows/policy-validation.yaml
name: Policy Validation

on:
  push:
    paths:
      - 'policies/**'
      - '.github/workflows/policy-validation.yaml'
  pull_request:
    paths:
      - 'policies/**'

jobs:
  validate:
    name: Validate Policies
    runs-on: ubuntu-latest

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install PolicyBind
        run: pip install policybind

      - name: Validate Policy Syntax
        run: |
          for file in policies/*.yaml; do
            echo "Validating: $file"
            policybind policy validate "$file"
          done

      - name: Run Policy Tests
        run: |
          policybind policy test policies/ \\
            --fixtures tests/policy_fixtures.yaml \\
            --format junit \\
            --output test-results/policy-tests.xml

      - name: Upload Test Results
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: policy-test-results
          path: test-results/

      - name: Publish Test Results
        uses: EnricoMi/publish-unit-test-result-action@v2
        if: always()
        with:
          files: test-results/policy-tests.xml

  deploy:
    name: Deploy Policies
    runs-on: ubuntu-latest
    needs: validate
    if: github.ref == 'refs/heads/main'

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install PolicyBind
        run: pip install policybind

      - name: Deploy Policies
        env:
          POLICYBIND_API_URL: ${{ secrets.POLICYBIND_API_URL }}
          POLICYBIND_API_KEY: ${{ secrets.POLICYBIND_API_KEY }}
        run: |
          echo "Deploying policies to production..."
          policybind policy load policies/ \\
            --message "Deploy from commit ${{ github.sha }}"
          echo "Policies deployed successfully!"
'''

    print("\nGitHub Actions Workflow (.github/workflows/policy-validation.yaml):")
    print(github_workflow)

    print()

    # -------------------------------------------------------------------------
    # Step 5: GitLab CI Pipeline
    # -------------------------------------------------------------------------
    print("Step 5: GitLab CI Integration...")
    print("-" * 60)

    gitlab_ci = '''# .gitlab-ci.yml
stages:
  - validate
  - test
  - deploy

variables:
  PIP_CACHE_DIR: "$CI_PROJECT_DIR/.pip"

.policybind-setup:
  image: python:3.11-slim
  before_script:
    - pip install policybind
  cache:
    paths:
      - .pip/

validate-policies:
  extends: .policybind-setup
  stage: validate
  script:
    - |
      echo "=== Validating Policies ==="
      for file in policies/*.yaml; do
        echo "Validating: $file"
        policybind policy validate "$file"
      done
  rules:
    - changes:
        - policies/**/*

test-policies:
  extends: .policybind-setup
  stage: test
  script:
    - |
      echo "=== Testing Policies ==="
      policybind policy test policies/ \\
        --fixtures tests/policy_fixtures.yaml \\
        --format junit \\
        --output policy-tests.xml
  artifacts:
    when: always
    reports:
      junit: policy-tests.xml
  rules:
    - changes:
        - policies/**/*
        - tests/**/*

compliance-check:
  extends: .policybind-setup
  stage: test
  script:
    - |
      echo "=== Compliance Check ==="
      policybind registry check-compliance --all \\
        --framework eu-ai-act \\
        --format json \\
        --output compliance-report.json
  artifacts:
    paths:
      - compliance-report.json
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"

deploy-policies:
  extends: .policybind-setup
  stage: deploy
  script:
    - |
      echo "=== Deploying Policies ==="
      policybind policy load policies/ \\
        --message "Deploy from pipeline $CI_PIPELINE_ID"
  environment:
    name: production
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
      changes:
        - policies/**/*
'''

    print("\nGitLab CI Pipeline (.gitlab-ci.yml):")
    print(gitlab_ci)

    print()

    # -------------------------------------------------------------------------
    # Step 6: Jenkins Pipeline
    # -------------------------------------------------------------------------
    print("Step 6: Jenkins Pipeline Integration...")
    print("-" * 60)

    jenkinsfile = '''// Jenkinsfile
pipeline {
    agent {
        docker {
            image 'python:3.11-slim'
            args '-v pip-cache:/root/.cache/pip'
        }
    }

    environment {
        POLICYBIND_API_URL = credentials('policybind-api-url')
        POLICYBIND_API_KEY = credentials('policybind-api-key')
    }

    stages {
        stage('Setup') {
            steps {
                sh 'pip install policybind'
            }
        }

        stage('Validate Policies') {
            steps {
                script {
                    def policyFiles = findFiles(glob: 'policies/*.yaml')
                    policyFiles.each { file ->
                        echo "Validating: ${file.name}"
                        sh "policybind policy validate ${file.path}"
                    }
                }
            }
        }

        stage('Test Policies') {
            steps {
                sh '''
                    policybind policy test policies/ \\
                        --fixtures tests/policy_fixtures.yaml \\
                        --format junit \\
                        --output test-results/policy-tests.xml
                '''
            }
            post {
                always {
                    junit 'test-results/policy-tests.xml'
                }
            }
        }

        stage('Compliance Check') {
            when {
                branch 'main'
            }
            steps {
                sh '''
                    policybind registry check-compliance --all \\
                        --format html \\
                        --output compliance-report.html
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'compliance-report.html'
                }
            }
        }

        stage('Deploy Policies') {
            when {
                branch 'main'
            }
            steps {
                sh """
                    policybind policy load policies/ \\
                        --message "Deploy from build ${BUILD_NUMBER}"
                """
            }
        }
    }

    post {
        failure {
            slackSend(
                channel: '#ai-governance',
                color: 'danger',
                message: "Policy deployment failed: ${BUILD_URL}"
            )
        }
        success {
            slackSend(
                channel: '#ai-governance',
                color: 'good',
                message: "Policies deployed successfully: ${BUILD_URL}"
            )
        }
    }
}
'''

    print("\nJenkins Pipeline (Jenkinsfile):")
    print(jenkinsfile)

    print()

    # -------------------------------------------------------------------------
    # Step 7: Pre-Commit Hook
    # -------------------------------------------------------------------------
    print("Step 7: Pre-Commit Hook Integration...")
    print("-" * 60)

    precommit_config = '''# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: policybind-validate
        name: Validate PolicyBind Policies
        entry: policybind policy validate
        language: system
        files: ^policies/.*\\.ya?ml$
        pass_filenames: true

      - id: policybind-test
        name: Test PolicyBind Policies
        entry: bash -c 'policybind policy test policies/ --fixtures tests/policy_fixtures.yaml --quiet'
        language: system
        files: ^(policies|tests)/.*\\.ya?ml$
        pass_filenames: false
'''

    print("\nPre-Commit Configuration (.pre-commit-config.yaml):")
    print(precommit_config)

    precommit_hook = '''#!/bin/bash
# .git/hooks/pre-commit
# Validates policies before commit

echo "=== PolicyBind Pre-Commit Validation ==="

# Find changed policy files
POLICY_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep -E '^policies/.*\\.ya?ml$')

if [ -z "$POLICY_FILES" ]; then
    echo "No policy files changed, skipping validation."
    exit 0
fi

ERRORS=0

for file in $POLICY_FILES; do
    echo "Validating: $file"
    if ! policybind policy validate "$file" --quiet; then
        echo "  FAILED: $file"
        ERRORS=$((ERRORS + 1))
    fi
done

if [ $ERRORS -gt 0 ]; then
    echo ""
    echo "Pre-commit validation failed: $ERRORS errors"
    echo "Please fix the policy errors before committing."
    exit 1
fi

echo "Pre-commit validation passed!"
exit 0
'''

    print("\nPre-Commit Hook Script (.git/hooks/pre-commit):")
    print(precommit_hook)

    print()

    # -------------------------------------------------------------------------
    # Step 8: Policy Drift Detection
    # -------------------------------------------------------------------------
    print("Step 8: Policy Drift Detection...")
    print("-" * 60)

    drift_detection = '''#!/bin/bash
# ci/detect-drift.sh
# Detects drift between deployed policies and source

set -e

echo "=== PolicyBind Drift Detection ==="

# Get current deployed version
DEPLOYED_VERSION=$(policybind policy show --format json | jq -r '.version')
echo "Deployed version: $DEPLOYED_VERSION"

# Get source version
SOURCE_VERSION=$(policybind policy validate policies/ --format json | jq -r '.version')
echo "Source version: $SOURCE_VERSION"

if [ "$DEPLOYED_VERSION" != "$SOURCE_VERSION" ]; then
    echo ""
    echo "DRIFT DETECTED!"
    echo "Deployed: $DEPLOYED_VERSION"
    echo "Source:   $SOURCE_VERSION"
    echo ""
    echo "Showing differences..."
    policybind policy diff "$DEPLOYED_VERSION" "$SOURCE_VERSION" --output drift-report.md
    exit 2
fi

echo ""
echo "No drift detected. Policies are in sync."
exit 0
'''

    print("\nDrift Detection Script (ci/detect-drift.sh):")
    print(drift_detection)

    scheduled_drift = '''# .github/workflows/drift-detection.yaml
name: Policy Drift Detection

on:
  schedule:
    - cron: '0 */6 * * *'  # Every 6 hours
  workflow_dispatch:

jobs:
  detect-drift:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install PolicyBind
        run: pip install policybind

      - name: Detect Drift
        id: drift
        env:
          POLICYBIND_API_URL: ${{ secrets.POLICYBIND_API_URL }}
          POLICYBIND_API_KEY: ${{ secrets.POLICYBIND_API_KEY }}
        run: |
          ./ci/detect-drift.sh || echo "drift=true" >> $GITHUB_OUTPUT

      - name: Create Issue on Drift
        if: steps.drift.outputs.drift == 'true'
        uses: actions/github-script@v7
        with:
          script: |
            github.rest.issues.create({
              owner: context.repo.owner,
              repo: context.repo.repo,
              title: 'Policy Drift Detected',
              body: 'Drift detected between source and deployed policies. See workflow run for details.',
              labels: ['policy-drift', 'needs-attention']
            })
'''

    print("\nScheduled Drift Detection (.github/workflows/drift-detection.yaml):")
    print(scheduled_drift)

    print()

    # -------------------------------------------------------------------------
    # Step 9: Rollback Procedure
    # -------------------------------------------------------------------------
    print("Step 9: Rollback Procedure...")
    print("-" * 60)

    rollback_script = '''#!/bin/bash
# ci/rollback-policies.sh
# Rollback to a previous policy version

set -e

VERSION="${1:-}"

if [ -z "$VERSION" ]; then
    echo "Usage: $0 <version>"
    echo ""
    echo "Available versions:"
    policybind policy history --limit 10
    exit 1
fi

echo "=== PolicyBind Rollback ==="
echo "Rolling back to version: $VERSION"

# Confirm rollback (in CI, use --force)
if [ -z "$CI" ]; then
    read -p "Are you sure? (y/N) " confirm
    if [ "$confirm" != "y" ]; then
        echo "Rollback cancelled."
        exit 0
    fi
fi

# Perform rollback
policybind policy rollback "$VERSION" --force

echo ""
echo "Rollback complete!"
echo ""
echo "Current policy version:"
policybind policy show --format json | jq '.version'
'''

    print("\nRollback Script (ci/rollback-policies.sh):")
    print(rollback_script)

    print()

    # -------------------------------------------------------------------------
    # Step 10: Environment Configuration
    # -------------------------------------------------------------------------
    print("Step 10: Environment Configuration...")
    print("-" * 60)

    env_config = '''# Environment Variables for CI/CD

# PolicyBind API Configuration
POLICYBIND_API_URL=https://policybind.example.com
POLICYBIND_API_KEY=<your-api-key>

# Database Configuration (for local testing)
POLICYBIND_DATABASE_PATH=./data/policybind.db

# Policy Configuration
POLICYBIND_POLICY_PATH=./policies/
POLICYBIND_CONFIG_PATH=./policybind.yaml

# Logging
POLICYBIND_LOG_LEVEL=INFO
POLICYBIND_LOG_FORMAT=json

# Feature Flags
POLICYBIND_STRICT_MODE=true
POLICYBIND_DRY_RUN=false

# CI/CD Specific
CI=true
POLICYBIND_NON_INTERACTIVE=true
'''

    print("\nEnvironment Configuration (.env.ci):")
    print(env_config)

    docker_compose = '''# docker-compose.ci.yml
version: '3.8'

services:
  policybind:
    image: policybind/server:latest
    environment:
      - POLICYBIND_LOG_LEVEL=INFO
      - POLICYBIND_DATABASE_PATH=/data/policybind.db
    volumes:
      - ./policies:/policies:ro
      - policybind-data:/data
    ports:
      - "8080:8080"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/v1/health"]
      interval: 10s
      timeout: 5s
      retries: 3

  policy-tests:
    image: python:3.11-slim
    depends_on:
      policybind:
        condition: service_healthy
    environment:
      - POLICYBIND_API_URL=http://policybind:8080
    volumes:
      - ./tests:/tests:ro
      - ./policies:/policies:ro
    command: >
      bash -c "
        pip install policybind &&
        policybind policy test /policies/ --fixtures /tests/policy_fixtures.yaml
      "

volumes:
  policybind-data:
'''

    print("\nDocker Compose for CI (docker-compose.ci.yml):")
    print(docker_compose)

    print()

    # -------------------------------------------------------------------------
    # Summary
    # -------------------------------------------------------------------------
    print("=" * 60)
    print("Example completed successfully!")
    print("=" * 60)
    print()
    print("Key Takeaways:")
    print("  1. Use 'policybind policy validate' for syntax checking")
    print("  2. Use 'policybind policy test' with fixtures for testing")
    print("  3. Integrate validation into pre-commit hooks")
    print("  4. Run policy tests in CI pipelines")
    print("  5. Implement drift detection for production safety")
    print("  6. Have rollback procedures ready")
    print()
    print("Exit Codes:")
    print("  0: Success")
    print("  1: General error")
    print("  2: Policy violation or validation error")
    print("  3: Configuration error")
    print()
    print("Best Practices:")
    print("  - Store policies in version control")
    print("  - Require PR reviews for policy changes")
    print("  - Use separate environments (dev/staging/prod)")
    print("  - Implement gradual rollout for policy changes")
    print("  - Monitor policy enforcement after deployments")
    print("  - Document all policy changes with commit messages")
    print()
    print("Files to Create:")
    print("  - .github/workflows/policy-validation.yaml (GitHub Actions)")
    print("  - .gitlab-ci.yml (GitLab CI)")
    print("  - Jenkinsfile (Jenkins)")
    print("  - .pre-commit-config.yaml (Pre-commit hooks)")
    print("  - ci/validate-policies.sh")
    print("  - ci/test-policies.sh")
    print("  - ci/detect-drift.sh")
    print("  - ci/rollback-policies.sh")
    print("  - tests/policy_fixtures.yaml")

    return 0


if __name__ == "__main__":
    sys.exit(main())
