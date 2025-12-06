## Overview

**EPMPS** is a collection of PowerShell scripts designed to facilitate and automate interactions with the **CyberArk Endpoint Privilege Manager (EPM) REST API**.

This repository serves as a toolkit for EPM administrators and developers looking to programmatically manage policies, agents, and configurations. While the repository contains various examples, the core of this project is the `EPMBaseFunc.ps1` script, which standardizes API calls and handles API limitations.

> **Reference:** Official [CyberArk EPM Developer Documentation](https://docs.cyberark.com/epm/latest/en/content/landingpages/lpdeveloper.htm).

-----

## ⚠️ Disclaimer

> **PLEASE READ CAREFULLY:**
>
> These scripts are provided **"AS IS"** without warranty of any kind, either express or implied.
>
>   * These are **community-driven examples** and are **not** official CyberArk products.
>   * Running scripts against your EPM environment can make significant changes. **Always test thoroughly in a non-production (development) set** before running against your production environment.
>   * The use of these scripts is entirely at the **user's own responsibility**. The author accepts no liability for any data loss, service interruption, or configuration errors resulting from the use of this code.

-----

## Key Feature: `EPMBaseFunc.ps1`

The heart of this repository is `EPMBaseFunc.ps1`. This script acts as a wrapper/template library that abstracts the complexity of raw HTTP requests.

### Why use `EPMBaseFunc.ps1`?

Instead of writing `Invoke-RestMethod` from scratch for every script, you can use this file to gain access to standardized functions.

#### 1\. Rate Limiting Management

CyberArk EPM enforces strict limits on the number of API requests allowed per minute.

  * **Automatic Throttling:** `EPMBaseFunc.ps1` includes logic to track API consumption.
  * **Wait & Retry:** If the script approaches the request limit, it will intelligently pause execution to comply with API quotas, preventing `429 Too Many Requests` errors and ensuring your automation runs smoothly without getting banned.

#### 2\. Standardized Error Handling

  * Provides consistent logging and error reporting for HTTP failures (4xx and 5xx errors).

#### 3\. Simplified Authentication

  * Streamlines the token retrieval and session management process.

-----

## Getting Started

### Prerequisites

  * **PowerShell:** Version 5.1 or PowerShell Core 7+.
  * **EPM Credentials:** You will need a valid EPM Username/Password with appropriate permissions.
  * **EPM Server URL:** The address of your EPM SaaS instance (e.g., `https://<subdomain>.epm.cyberark.com`).