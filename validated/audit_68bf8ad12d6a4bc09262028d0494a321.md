### Title
Unbounded SQL Query with No Pagination in `/transaction-nodes?collection=HISTORY` Causes Authenticated DoS

### Summary
The `GET /transaction-nodes` endpoint, when called with `collection=HISTORY`, executes a SQL query against the entire `transaction` table with no `LIMIT` clause and no user-scoping filter. As the organization's transaction history grows, any authenticated user can trigger a query that fetches every historical transaction in the database in a single response, exhausting server memory and database resources and causing a sustained denial of service.

### Finding Description

**Root cause — no LIMIT in the generated SQL:**

`getTransactionNodesQuery` in `back-end/libs/common/src/sql/queries/transaction.queries.ts` builds a CTE-based SQL query. The final `SELECT` has no `LIMIT` or `OFFSET` clause: [1](#0-0) 

**Root cause — HISTORY collection passes no user context:**

In `transaction-nodes.service.ts`, every other collection (`READY_FOR_REVIEW`, `READY_TO_SIGN`, etc.) passes `user` and role flags to `getTransactionNodesQuery`, which causes `buildWhereClause` to add per-user eligibility conditions. The `HISTORY` case omits both: [2](#0-1) 

When `user` is absent, `buildWhereClause` skips `buildEligibilityConditions` entirely and only applies the status/network filter: [3](#0-2) 

The result is a query of the form:
```sql
WHERE t.status = ANY($1) AND t.mirrorNetwork = $2
  AND (t.status = ANY($3))   -- terminal statuses only
ORDER BY rt.tx_created_at DESC
-- no LIMIT
```

This returns every terminal-status transaction in the database for the given network, across all users, in one unbounded result set.

**Exposed endpoint — no pagination guard:**

The controller accepts the `collection` enum value directly and returns the full array: [4](#0-3) 

The `PaginationParams` decorator (which enforces `size ≤ 100`) is not used here. The endpoint is intentionally designed to return all items in a single request, as documented in the k6 test comments: [5](#0-4) 

**Secondary instance — `getTransactionsToSign` unbounded fetch + loop:**

`transactions.service.ts` fetches every non-terminal transaction with no `take` limit, then iterates over the full result set calling `userKeysToSign` per row: [6](#0-5) 

### Impact Explanation

- **Memory exhaustion**: The Node.js API process must hold the entire result set in memory before serializing it. With tens of thousands of historical transactions (each containing `transactionBytes` as a hex blob), a single request can consume hundreds of megabytes.
- **Database resource exhaustion**: The unbounded CTE query holds a full table scan open, consuming PostgreSQL worker memory and connection slots for the duration.
- **Cascading DoS**: Because the endpoint is synchronous within the NestJS request lifecycle, concurrent requests from a single authenticated user can saturate the event loop and database connection pool, making the API unresponsive for all users.
- **No recovery without intervention**: The table only grows; there is no mechanism to shrink it. The degradation is permanent and worsens over time.

### Likelihood Explanation

- **Attacker precondition**: Possession of a valid JWT token for any verified organization user — the lowest privilege level in the system.
- **Trigger**: A single HTTP GET request: `GET /transaction-nodes?collection=HISTORY&network=mainnet`.
- **Realistic scenario**: In a production organization that has processed thousands of transactions over months, the HISTORY collection will naturally grow to a size that makes this query expensive. An attacker (or even a legitimate user with a slow client) repeatedly calling this endpoint amplifies the impact.
- **No rate limiting observed** in the controller or guards for this endpoint.

### Recommendation

1. **Add a `LIMIT` clause** to `getTransactionNodesQuery` and expose `limit`/`offset` parameters so the endpoint supports pagination, consistent with all other endpoints in the API.
2. **Apply user scoping to HISTORY**: pass `user` and appropriate role flags (e.g., `{ creator: true, signer: true, observer: true, approver: true }`) to `getTransactionNodesQuery` for the HISTORY collection, so each user only retrieves their own historical transactions.
3. **Enforce a hard cap** in the controller (e.g., max 500 rows) until full pagination is implemented.
4. **Fix `getTransactionsToSign`**: add a `take: limit` constraint to the `repo.find()` call and perform the key-matching filter in SQL rather than in-process.

### Proof of Concept

**Setup**: An organization has accumulated N ≥ 10,000 executed/failed/expired transactions on `mainnet`.

**Steps**:
1. Authenticate as any verified organization user and obtain a JWT token.
2. Send:
   ```
   GET /transaction-nodes?collection=HISTORY&network=mainnet
   Authorization: Bearer <token>
   ```
3. The server executes the unbounded CTE query, fetching all N rows with no LIMIT.
4. The Node.js process allocates memory proportional to N × (average transaction size).
5. Repeat the request concurrently (e.g., 10 parallel requests) to exhaust the PostgreSQL connection pool and Node.js heap.
6. **Expected outcome**: API response times degrade to timeouts; other users receive 503/504 errors; the service requires a restart to recover.

**Amplification**: An attacker can also create transactions (via the normal transaction creation flow) to grow the HISTORY collection faster, then trigger the DoS. Each created-and-executed transaction permanently increases the cost of every future HISTORY query.

### Citations

**File:** back-end/libs/common/src/sql/queries/transaction.queries.ts (L215-246)
```typescript
function buildWhereClause(
  sql: SqlBuilderService,
  filters?: TransactionFilters,
  userContext?: { user: User; roles: Roles },
): WhereClauseResult {
  const conditions: string[] = [];
  const values: any[] = [];
  let paramIndex = 1;

  const addParam = (value: any): string => {
    values.push(value);
    return `$${paramIndex++}`;
  };

  if (filters) {
    conditions.push(...buildFilterConditions(sql, filters, addParam));
  }

  const eligibilityConditions: string[] = [];

  if (userContext) {
    const { user, roles } = userContext;
    eligibilityConditions.push(...buildEligibilityConditions(sql, user, roles, addParam));
  }

  const statusParam = addParam(TERMINAL_STATUSES);
  eligibilityConditions.push(`t.${sql.col(Transaction, 'status')} = ANY(${statusParam})`);

  conditions.push(`(${eligibilityConditions.join(' OR ')})`);

  return { clause: conditions.join(' AND '), values, addParam };
}
```

**File:** back-end/libs/common/src/sql/queries/transaction.queries.ts (L248-355)
```typescript
export function getTransactionNodesQuery(
  sql: SqlBuilderService,
  filters: TransactionFilters,
  user?: User,
  roles?: Roles,
): SqlQuery {
  const { clause, values } = buildWhereClause(
    sql,
    filters,
    user && roles ? { user, roles } : undefined,
  );

  const text = `
      WITH eligible_transactions AS (
          SELECT
              t.${sql.col(Transaction, 'id')} AS transaction_id,
              gi.${sql.col(TransactionGroupItem, 'groupId')} AS group_id,
              t.${sql.col(Transaction, 'description')} AS tx_description,
              t.${sql.col(Transaction, 'createdAt')} AS tx_created_at,
              t.${sql.col(Transaction, 'validStart')} AS tx_valid_start,
              t.${sql.col(Transaction, 'updatedAt')} AS tx_updated_at,
              t.${sql.col(Transaction, 'executedAt')} AS tx_executed_at,
              t.${sql.col(Transaction, 'status')} AS tx_status,
              t.${sql.col(Transaction, 'statusCode')} AS tx_status_code,
              t.${sql.col(Transaction, 'transactionId')} AS sdk_transaction_id,
              t.${sql.col(Transaction, 'type')} AS transaction_type,
              t.${sql.col(Transaction, 'isManual')} AS is_manual,
              ROW_NUMBER() OVER (
                PARTITION BY gi.${sql.col(TransactionGroupItem, 'groupId')}
                ORDER BY t.${sql.col(Transaction, 'createdAt')} DESC
              ) AS rn
          FROM ${sql.table(Transaction)} t
                   LEFT JOIN ${sql.table(TransactionGroupItem)} gi
                             ON gi.${sql.col(TransactionGroupItem, 'transactionId')} = t.${sql.col(Transaction, 'id')}
          WHERE ${clause}
      ),
           group_aggregates AS (
               SELECT
                   group_id,
                   COUNT(DISTINCT tx_status) AS distinct_statuses,
                   MAX(tx_status) AS uniform_status,
                   COUNT(DISTINCT tx_status_code) AS distinct_status_codes,
                   MAX(tx_status_code) AS uniform_status_code,
                   MIN(tx_valid_start) AS min_valid_start,
                   MAX(tx_updated_at) AS max_updated_at,
                   MAX(tx_executed_at) AS max_executed_at
               FROM eligible_transactions
               WHERE group_id IS NOT NULL
               GROUP BY group_id
           ),
           representative_transactions AS (
               SELECT
                   transaction_id,
                   group_id,
                   tx_description,
                   tx_created_at,
                   tx_valid_start,
                   tx_updated_at,
                   tx_executed_at,
                   tx_status,
                   tx_status_code,
                   sdk_transaction_id,
                   transaction_type,
                   is_manual
               FROM eligible_transactions
               WHERE group_id IS NULL OR rn = 1
           )
      SELECT
          CASE WHEN rt.group_id IS NULL THEN rt.transaction_id END AS transaction_id,
          rt.group_id AS group_id,
          COALESCE(tg.${sql.col(TransactionGroup, 'description')}, rt.tx_description) AS description,
          COALESCE(tg.${sql.col(TransactionGroup, 'createdAt')}, rt.tx_created_at) AS created_at,
          COALESCE(ga.min_valid_start, rt.tx_valid_start) AS valid_start,
          COALESCE(ga.max_updated_at, rt.tx_updated_at) AS updated_at,
          COALESCE(ga.max_executed_at, rt.tx_executed_at) AS executed_at,
          CASE
              WHEN rt.group_id IS NULL THEN rt.tx_status
              WHEN ga.distinct_statuses = 1 THEN ga.uniform_status
              ELSE NULL
              END AS status,
          CASE
              WHEN rt.group_id IS NULL THEN rt.tx_status_code
              WHEN ga.distinct_status_codes = 1 THEN ga.uniform_status_code
              ELSE NULL
              END AS status_code,
          CASE WHEN rt.group_id IS NULL THEN rt.sdk_transaction_id END AS sdk_transaction_id,
          CASE WHEN rt.group_id IS NULL THEN rt.transaction_type END AS transaction_type,
          CASE WHEN rt.group_id IS NULL THEN rt.is_manual END AS is_manual,
          (
              SELECT COUNT(*)::int
              FROM ${sql.table(TransactionGroupItem)} gi_all
              WHERE gi_all.${sql.col(TransactionGroupItem, 'groupId')} = rt.group_id
          ) AS group_item_count,
          (
              SELECT COUNT(DISTINCT transaction_id)::int
              FROM eligible_transactions et_inner
              WHERE et_inner.group_id = rt.group_id
          ) AS group_collected_count
      FROM representative_transactions rt
               LEFT JOIN ${sql.table(TransactionGroup)} tg
                         ON tg.${sql.col(TransactionGroup, 'id')} = rt.group_id
               LEFT JOIN group_aggregates ga
                         ON ga.group_id = rt.group_id
      ORDER BY rt.tx_created_at DESC
  `;

  return { text, values };
}
```

**File:** back-end/apps/api/src/transactions/nodes/transaction-nodes.service.ts (L103-117)
```typescript
      case TransactionNodeCollection.HISTORY: {
        statusFilter = statusFilter?.length ? statusFilter : TRANSACTION_STATUS_COLLECTIONS.HISTORY;
        transactionTypeFilter = transactionTypeFilter?.length ? transactionTypeFilter : null;
        const query = getTransactionNodesQuery(
          this.sqlBuilder,
          {
            statuses: statusFilter,
            types: transactionTypeFilter,
            mirrorNetwork: network,
          }
        );

        rows = await this.entityManager.query(query.text, query.values);
        break;
      }
```

**File:** back-end/apps/api/src/transactions/nodes/transaction-nodes.controller.ts (L41-56)
```typescript
  @Get()
  getTransactionNodes(
    @GetUser() user: User,
    @Query('collection', TransactionNodeCollectionPipe) collection: TransactionNodeCollection,
    @Query('network') network: string,
    @Query('status', TransactionStatusFilterPipe) statusFilter: TransactionStatus[],
    @Query('transactionType', TransactionTypeFilterPipe) transactionTypeFilter: TransactionType[],
  ): Promise<TransactionNodeDto[]> {
    return this.transactionNodesService.getTransactionNodes(
      user,
      collection,
      network,
      statusFilter,
      transactionTypeFilter,
    );
  }
```

**File:** automation/k6/src/config/environments.ts (L38-43)
```typescript
 * Build optimized transaction-nodes endpoint URL
 * Uses the new /transaction-nodes endpoint (PR #2161) which returns all items in a single request
 */
function buildTransactionNodesEndpoint(collection: string): string {
  return `/transaction-nodes?collection=${collection}&network=${NETWORK}`;
}
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L295-317)
```typescript
    const transactions = await this.repo.find({
      where: whereForUser,
      relations: ['groupItem'],
      order,
    });

    for (const transaction of transactions) {
      /* Check if the user should sign the transaction */
      try {
        const keysToSign = await this.userKeysToSign(transaction, user);
        if (keysToSign.length > 0) result.push({ transaction, keysToSign });
      } catch (error) {
        console.log(error);
      }
    }

    return {
      totalItems: result.length,
      items: result.slice(offset, offset + limit),
      page,
      size,
    };
  }
```
