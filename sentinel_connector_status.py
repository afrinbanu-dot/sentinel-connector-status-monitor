import json
import requests
from datetime import timedelta

from azure.identity import InteractiveBrowserCredential
from azure.monitor.query import LogsQueryClient

# CONFIGURATION
TENANT_ID = ""
SUBSCRIPTION_ID = ""
RESOURCE_GROUP = ""
WORKSPACE_NAME = ""
WORKSPACE_ID = ""

# AUTHENTICATION
credential = InteractiveBrowserCredential()

token = credential.get_token(
    "https://management.azure.com/.default"
).token

headers = {
    "Authorization": f"Bearer {token}",
    "Content-Type": "application/json"
}

# STORAGE
all_connectors = {}

# HELPER
def add_connector(
    name,
    status,
    source,
    details=None
):

    if name not in all_connectors:

        all_connectors[name] = {
            "name": name,
            "status": status,
            "source": source,
            "details": details or {}
        }

    else:

        existing = all_connectors[name]

        priority = {
            "ACTIVE": 5,
            "INSTALLED": 4,
            "CONFIGURED": 3,
            "NO DATA": 2,
            "UNKNOWN": 1
        }

        old_score = priority.get(
            existing["status"],
            0
        )

        new_score = priority.get(
            status,
            0
        )

        if new_score > old_score:

            all_connectors[name] = {
                "name": name,
                "status": status,
                "source": source,
                "details": details or {}
            }


print("\n===================================================")
print(" MICROSOFT SENTINEL CONNECTOR INVENTORY ")
print("===================================================\n")


# 1. LEGACY CONNECTORS API
print("===================================================")
print(" FETCHING LEGACY CONNECTORS ")
print("===================================================\n")

legacy_url = (
    f"https://management.azure.com/subscriptions/{SUBSCRIPTION_ID}"
    f"/resourceGroups/{RESOURCE_GROUP}"
    f"/providers/Microsoft.OperationalInsights/workspaces/{WORKSPACE_NAME}"
    f"/providers/Microsoft.SecurityInsights/dataConnectors"
    f"?api-version=2025-09-01"
)

try:

    response = requests.get(
        legacy_url,
        headers=headers
    )

    if response.status_code == 200:

        data = response.json()

        for item in data.get("value", []):

            props = item.get("properties", {})

            connector_name = props.get(
                "connectorDefinitionName",
                item.get("name")
            )

            is_active = props.get(
                "isActive",
                False
            )

            status = (
                "ACTIVE"
                if is_active
                else "INSTALLED"
            )

            add_connector(
                connector_name,
                status,
                "Legacy API"
            )

            print(
                f"[LEGACY] "
                f"{connector_name} "
                f"=> {status}"
            )

    else:

        print(response.text)

except Exception as e:

    print(f"Legacy API Error: {str(e)}")


# 2. CONTENT HUB CONNECTORS
print("\n===================================================")
print(" FETCHING CONTENT HUB CONNECTORS ")
print("===================================================\n")

content_url = (
    f"https://management.azure.com/subscriptions/{SUBSCRIPTION_ID}"
    f"/resourceGroups/{RESOURCE_GROUP}"
    f"/providers/Microsoft.OperationalInsights/workspaces/{WORKSPACE_NAME}"
    f"/providers/Microsoft.SecurityInsights/contentPackages"
    f"?api-version=2024-03-01"
)

try:

    response = requests.get(
        content_url,
        headers=headers
    )

    if response.status_code == 200:

        data = response.json()

        for item in data.get("value", []):

            props = item.get(
                "properties",
                {}
            )

            display_name = props.get(
                "displayName",
                item.get("name")
            )

            content_kind = props.get(
                "contentKind",
                ""
            )

            package_kind = props.get(
                "contentProductId",
                ""
            )

            if (
                content_kind == "DataConnector"
                or "DataConnector" in package_kind
            ):

                add_connector(
                    display_name,
                    "INSTALLED",
                    "Content Hub"
                )

                print(
                    f"[CONTENT HUB] "
                    f"{display_name}"
                )

    else:

        print(response.text)

except Exception as e:

    print(f"Content Hub Error: {str(e)}")


# 3. DCR / AMA CONNECTOR
print("\n===================================================")
print(" FETCHING DCR CONNECTORS ")
print("===================================================\n")

dcr_url = (
    f"https://management.azure.com/subscriptions/{SUBSCRIPTION_ID}"
    f"/resourceGroups/{RESOURCE_GROUP}"
    f"/providers/Microsoft.Insights/dataCollectionRules"
    f"?api-version=2023-03-11"
)

try:

    response = requests.get(
        dcr_url,
        headers=headers
    )

    if response.status_code == 200:

        data = response.json()

        for item in data.get("value", []):

            dcr_name = item.get("name")

            add_connector(
                dcr_name,
                "CONFIGURED",
                "DCR / AMA"
            )

            print(
                f"[DCR] "
                f"{dcr_name}"
            )

    else:

        print(response.text)

except Exception as e:

    print(f"DCR Error: {str(e)}")


# 4. ACTIVE LOG INGESTION
print("\n===================================================")
print(" DETECTING ACTIVE INGESTION ")
print("===================================================\n")

logs_client = LogsQueryClient(
    credential
)


# KNOWN TABLE MAPPINGS
CONNECTOR_TABLES = {

    "SigninLogs": "Microsoft Entra ID",
    "AuditLogs": "Microsoft Entra Audit",

    "SecurityAlert": "Microsoft Defender XDR",

    "DeviceEvents": "Microsoft Defender for Endpoint",

    "DeviceNetworkEvents":
        "Defender Network Events",

    "IdentityLogonEvents":
        "Microsoft Defender for Identity",

    "CloudAppEvents":
        "Microsoft Defender for Cloud Apps",

    "OfficeActivity":
        "Microsoft 365",

    "AzureActivity":
        "Azure Activity",

    "SecurityEvent":
        "Windows Security Events via AMA",

    "Heartbeat":
        "Azure Monitor Agent",

    "Syslog":
        "Linux Syslog",

    "CommonSecurityLog":
        "CEF / Syslog Connector",

    "SAPLogServ_CL":
        "SAP LogServ"
}

query_parts = []

for table_name, connector_name in CONNECTOR_TABLES.items():

    query_parts.append(f"""
    (
        {table_name}
        | summarize LastLog=max(TimeGenerated)
        | extend TableName="{table_name}"
        | extend Connector="{connector_name}"
    )
    """)

QUERY = (
    "union isfuzzy=true\n"
    + ",\n".join(query_parts)
)

QUERY += """
| extend DelayMinutes =
    datetime_diff(
        "minute",
        now(),
        LastLog
    )
"""

try:

    response = logs_client.query_workspace(
        workspace_id=WORKSPACE_ID,
        query=QUERY,
        timespan=timedelta(days=7)
    )

    if response.tables:

        table = response.tables[0]

        print(
            f"{'Connector':<45}"
            f"{'Status':<15}"
            f"{'Last Log':<35}"
        )

        print("-" * 95)

        for row in table.rows:

            last_log = row[0]
            table_name = row[1]
            connector_name = row[2]
            delay = row[3]

            if last_log is None:

                status = "NO DATA"

            else:

                if delay <= 60:

                    status = "ACTIVE"

                else:

                    status = "STALE"

            add_connector(
                connector_name,
                status,
                "Log Ingestion",
                {
                    "table": table_name,
                    "last_log": str(last_log),
                    "delay_minutes": delay
                }
            )

            print(
                f"{connector_name:<45}"
                f"{status:<15}"
                f"{str(last_log):<35}"
            )

except Exception as e:

    print(f"Log Query Error: {str(e)}")


# 5. DYNAMIC TABLE DISCOVERY
print("\n===================================================")
print(" DISCOVERING CUSTOM TABLES ")
print("===================================================\n")

dynamic_query = """
search *
| summarize LastLog=max(TimeGenerated)
    by $table
| order by LastLog desc
"""

try:

    response = logs_client.query_workspace(
        workspace_id=WORKSPACE_ID,
        query=dynamic_query,
        timespan=timedelta(days=7)
    )

    if response.tables:

        table = response.tables[0]

        for row in table.rows:

            table_name = row[0]
            last_log = row[1]

            # detect custom connectors
            if (
                "_CL" in table_name
                or "CrowdStrike" in table_name
                or "Prisma" in table_name
                or "WAF" in table_name
            ):

                connector_name = table_name

                add_connector(
                    connector_name,
                    "ACTIVE",
                    "Dynamic Table Discovery",
                    {
                        "table": table_name,
                        "last_log": str(last_log)
                    }
                )

                print(
                    f"[CUSTOM] "
                    f"{table_name}"
                )

except Exception as e:

    print(f"Dynamic Discovery Error: {str(e)}")


# FINAL RESULTS
print("\n===================================================")
print(" FINAL CONNECTOR INVENTORY ")
print("===================================================\n")

final_connectors = list(
    all_connectors.values()
)

print(
    json.dumps(
        final_connectors,
        indent=4
    )
)


# SUMMARY

print("\n===================================================")
print(" CONNECTOR SUMMARY ")
print("===================================================\n")

for connector in sorted(
    final_connectors,
    key=lambda x: x["name"]
):

    print(
        f"{connector['name']:<55}"
        f"{connector['status']:<15}"
        f"{connector['source']}"
    )