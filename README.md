# WebSped Order Import Automation

This project provides a Python-based automation layer for creating
orders in **WinSped** via the **WebSped** module.\
Instead of building custom APIs, deploying new services, or managing
additional authentication layers, this script uses WebSped itself as a
stable and secure "browser-API".

The result: a flexible, partner-friendly data import workflow that works
entirely within the existing LIS ecosystem.

## Key Features

-   Automates order creation in WebSped\
-   Uses JSON mapping files\
-   Supports CSV, JSON, XML\
-   Uploads documents into DMS\
-   Returns created order numbers\
-   No new API or servers needed

## Running the Importer

``` bash
python3 importer.py --config path/to/config.json
```

## Requirements

-   Python 3.8+
-   requests
-   beautifulsoup4

## Why This Approach?

Because WebSped already provides authentication, permissions,
validation, and workflow.\
We simply automate what a user would normally do manually.
