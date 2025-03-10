Cosmos DB Account Reader Role
DocumentDB Account Contributor Role
Cosmos DB Operator

Cosmos DB Built-in Data Contributor Role is missing from the Role Assignment.

You can add custom role, follow these steps: 

https://learn.microsoft.com/en-us/azure/cosmos-db/nosql/security/how-to-grant-data-plane-role-based-access?tabs=custom-definition%2Ccsharp&pivots=azure-interface-cli



# List role assignments for the Cosmos DB account
az role assignment list --scope <cosmos-db-resource-id> --output table

Database Name: LoanAppDatabase
Container Name: LoanAppDataContainer
Partition key: /LoanAppDataId