# Microsoft Security Baselines vs ACSC Hardening Implementation

## Overview

Microsoft Security Baselines and the ACSC (Australian Cyber Security Centre) Windows Hardening guidelines serve similar purposes but with different focuses and approaches. This document explains their relationship and how our implementation relates to both.

## What are Microsoft Security Baselines?

Microsoft Security Baselines are **Microsoft-recommended configuration settings** that provide:

- **Expert knowledge** from Microsoft security engineering teams, product groups, partners, and customers
- **Well-tested configurations** for over 3,000 Group Policy settings in Windows 10/11
- **Industry-standard approach** to security configuration
- **Consumable formats** like Group Policy Object (GPO) backups and MDM policies

### Key Characteristics:
- **Scope**: Broad coverage of Windows security features
- **Target**: Well-managed, security-conscious organizations
- **Approach**: Conservative, enterprise-focused settings
- **Format**: Group Policy Objects (GPOs), MDM policies
- **Tools**: Security Compliance Toolkit (SCT) with Policy Analyzer and LGPO tools

## What are ACSC Hardening Guidelines?

ACSC Windows Hardening guidelines are **Australian government-recommended** security configurations that provide:

- **Government-grade security** aligned with Australian cybersecurity requirements
- **Risk-based prioritization** (High, Medium, Low priority settings)
- **Specific threat mitigation** for contemporary attack vectors
- **Compliance alignment** with Australian government security frameworks

### Key Characteristics:
- **Scope**: Focused on specific high-impact security controls
- **Target**: Government agencies and security-conscious organizations
- **Approach**: Risk-prioritized, threat-focused settings
- **Format**: Implementation guidance and specific registry/policy settings
- **Tools**: No specific toolkit, requires manual implementation

## Comparison Matrix

| Aspect | Microsoft Security Baselines | ACSC Hardening Guidelines |
|--------|------------------------------|----------------------------|
| **Authority** | Microsoft (vendor) | ACSC (government agency) |
| **Scope** | Comprehensive (3000+ settings) | Focused (priority-based) |
| **Approach** | Conservative enterprise | Risk-based government |
| **Updates** | Regular (with Windows releases) | Periodic (threat-driven) |
| **Tools** | SCT, Policy Analyzer, LGPO | None (manual implementation) |
| **Format** | GPO backups, MDM | Implementation guidance |
| **Target** | Enterprise organizations | Government and high-security orgs |

## Our Implementation Approach

### Why We Chose ACSC Guidelines

1. **Authoritative Source**: ACSC represents government-grade cybersecurity expertise
2. **Risk Prioritization**: Clear high/medium/low priority classification
3. **Threat Focus**: Addresses contemporary attack vectors specifically
4. **Compliance Alignment**: Supports Australian government security requirements

### Dependencies and Prerequisites

### Windows Security Baseline Templates Required

**Important**: Our ACSC implementation has a **dependency on Windows Security Baseline templates** because:

1. **Extended Policy Definitions**: Many DSC resources (SecurityPolicyDsc, AuditPolicyDsc) require policy templates that are **not available in vanilla Windows**
2. **Group Policy Extensions**: The baseline installation adds policy categories and settings that our configurations reference
3. **Template Availability**: Without the baseline, many of our SecurityOption and AuditPolicySubcategory resources would fail

### Installation Requirement

Before deploying our ACSC configurations, you must:

```powershell
# Download and install Windows Security Baseline
# From: https://www.microsoft.com/download/details.aspx?id=55319
# This provides the necessary Group Policy templates (.admx/.adml files)
```

### What the Baseline Provides

- **Extended Group Policy templates** (.admx/.adml files)
- **Additional security policy categories** not in vanilla Windows
- **Enhanced audit policy subcategories** required by AuditPolicyDsc
- **Modern security options** referenced by SecurityPolicyDsc

## Compatibility with Microsoft Security Baselines

### Complementary Areas

Our ACSC implementation **complements** Microsoft Security Baselines in these areas:

- **Additional threat coverage**: ACSC guidelines address specific threats not covered in baselines
- **Government requirements**: Provides additional controls for regulated environments
- **Risk prioritization**: Offers clear implementation priority guidance
- **Modern deployment**: Uses Azure Machine Configuration for cloud-scale deployment

### Overlapping Settings

Some settings appear in both Microsoft Security Baselines and ACSC guidelines:

| Setting Category | Microsoft Baseline | ACSC Guidance | Our Implementation |
|------------------|-------------------|---------------|-------------------|
| **Password Policy** | Standard complexity | 15-char minimum | ACSC (stronger) |
| **Account Lockout** | Conservative settings | 5 attempts, 30 min | ACSC values |
| **Audit Policy** | Comprehensive logging | Priority-based logging | ACSC priorities |
| **UAC Settings** | Standard protection | Enhanced protection | ACSC (stronger) |
| **Windows Defender** | Default configuration | ASR rules enabled | ACSC (enhanced) |

### Potential Conflicts

When both are applied, consider these potential conflicts:

1. **Password length**: Microsoft baseline may be less restrictive than ACSC's 15-character requirement
2. **Audit scope**: Microsoft baselines enable more auditing; ACSC focuses on high-priority events
3. **Feature disabling**: ACSC may disable features that Microsoft baselines leave enabled

## Integration Strategy

### Option 1: ACSC Primary + Baseline Secondary
- Deploy ACSC configurations first (our implementation)
- Add Microsoft Security Baseline settings that don't conflict
- Use Policy Analyzer to identify conflicts and gaps

### Option 2: Layered Approach
- Microsoft Security Baseline as foundation
- ACSC configurations as additional hardening layer
- Explicit conflict resolution where settings overlap

### Option 3: Custom Hybrid Baseline
- Analyze both using Security Compliance Toolkit
- Create custom baseline combining strongest settings from both
- Document rationale for each setting choice

## Tools for Comparison and Analysis

### Security Compliance Toolkit (SCT)
Use Microsoft's SCT tools to analyze our ACSC implementation:

```powershell
# Compare ACSC configs against Microsoft baselines
PolicyAnalyzer.exe -baseline "Microsoft_Windows11_Baseline.PolicyRules" -compare "ACSC_Implementation.PolicyRules"

# Export our DSC configs to LGPO format for comparison
LGPO.exe /r "ACSCHighPriorityHardening.reg" /w "ACSC_High_Priority.pol"
```

### Recommended Analysis Workflow

1. **Export Microsoft Baseline**: Download latest Windows 11/10 security baseline from Microsoft
2. **Convert ACSC to GPO**: Use LGPO tool to convert our registry settings to Policy format
3. **Run Policy Analyzer**: Compare both configurations to identify overlaps and conflicts
4. **Document Decisions**: Create rationale document for setting choices
5. **Test Combined Config**: Validate merged configuration in test environment

## Recommendations

### For Most Organizations
- **Start with our ACSC implementation** (proven, government-grade security)
- **Supplement with Microsoft Baseline** settings that don't conflict
- **Use SCT Policy Analyzer** to identify and resolve conflicts

### For Government/High-Security Organizations
- **Use ACSC implementation as primary** (our solution)
- **Add specific Microsoft Baseline controls** based on risk assessment
- **Document compliance mapping** to relevant frameworks

### For Enterprise Organizations
- **Consider Microsoft Security Baseline** as foundation
- **Layer ACSC high-priority settings** for enhanced security
- **Customize based on specific threat model** and compliance requirements

## Validation and Testing

Before deploying any combined configuration:

1. **Test in isolated environment** to identify functional issues
2. **Validate security controls** are working as expected
3. **Check application compatibility** with hardened settings
4. **Document rollback procedures** for problematic settings
5. **Plan phased deployment** starting with non-critical systems

## Conclusion

Our ACSC Windows Hardening implementation provides **government-grade security** that can work standalone or be combined with Microsoft Security Baselines. The key is understanding that:

- **ACSC guidelines are more focused** on high-impact, contemporary threats
- **Microsoft baselines are more comprehensive** but potentially less aggressive
- **Both are valid approaches** with different strengths
- **Combination is possible** with proper analysis and testing

The Azure Machine Configuration approach we've implemented provides modern, scalable deployment regardless of which baseline strategy you choose.
