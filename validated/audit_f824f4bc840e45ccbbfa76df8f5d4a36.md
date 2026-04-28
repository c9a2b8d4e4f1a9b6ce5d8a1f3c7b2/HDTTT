### Title
Unbounded `GET /transaction-nodes?collection=HISTORY` Query Causes Server Resource Exhaustion (DoS)

### Summary

The `GET /transaction-nodes` endpoint with `collection=HISTORY` executes a SQL query with no `LIMIT` clause and no pagination, fetching every historical transaction in the database in a single request. Any authenticated user can trigger this endpoint. As the organization accumulates transactions over time, the query grows unboundedly, eventually exhausting server memory and database resources, causing denial of service for all users.

### Finding Description

**Root cause:** `getTransactionNodesQuery` in `back-end/libs/common/src/sql/queries/transaction.queries.ts` builds a complex multi-CTE SQL query with no `LIMIT` or `OFFSET` clause. [1](#0-0) 

The query is executed directly via `this.entityManager.query(query.text, query.values)` and all rows are mapped into memory: [2](#0-1) 

For the `HISTORY` collection specifically, **no user context is passed** to `getTransactionNodesQuery`, meaning the WHERE clause only filters by status — it returns every historical transaction across all users: [3](#0-2) 

The controller exposes this to any verified, authenticated user with no rate limiting or pagination parameters: [4](#0-3) 

The k6 load test explicitly confirms the design intent: "Uses optimized /transaction-nodes endpoint - returns all items in single request" and targets 500+ items: [5](#0-4) 

The SQL query itself involves multiple CTEs (`eligible_transactions`, `group_aggregates`, `representative_transactions`), correlated subqueries for `group_item_count` and `group_collected_count`, and a final `ORDER BY` — all executed over the full unbounded result set: [6](#0-5) 

**Secondary instance:** `getUsers` in `back-end/apps/api/src/users/users.service.ts` also calls `this.repo.find()` with no pagination, returning all users in a single query: [7](#0-6) 

### Impact Explanation

Historical transactions are terminal-state records (`CANCELED`, `REJECTED`, `EXECUTED`, `FAILED`, `EXPIRED`, `ARCHIVED`) that accumulate indefinitely and are never deleted. Over time, a single authenticated user repeatedly calling `GET /transaction-nodes?collection=HISTORY&network=<any>` will:

1. Force the database to scan and join an ever-growing set of rows.
2. Load the entire result set into Node.js heap memory.
3. Serialize the full payload into a single HTTP response.

At sufficient scale this causes OOM crashes of the API process or database query timeouts, making the service unavailable for all users. The impact is **permanent service degradation** that worsens monotonically as the platform is used normally — no special attacker action is needed beyond repeated authenticated requests.

### Likelihood Explanation

- **Attacker precondition:** Valid organization account (normal user, no admin required).
- **Trigger:** A single HTTP GET request to `/transaction-nodes?collection=HISTORY`.
- **Escalation path:** Repeated calls, or a single call after sufficient organic transaction accumulation.
- **No existing mitigation:** The controller accepts no `page`/`size` parameters for this endpoint; the SQL query has no `LIMIT`; there is no server-side response size cap or rate limit visible in the controller guards.

The k6 test targeting 500 items at sub-1-second response time confirms the team is aware of volume but has not added a bound.

### Recommendation

1. Add `LIMIT` / `OFFSET` parameters to `getTransactionNodesQuery` and thread them through `getTransactionNodes` and the controller.
2. Enforce a maximum page size (e.g., 200 rows) server-side regardless of client input.
3. Add a server-side rate limit on the `/transaction-nodes` endpoint.
4. For the `HISTORY` collection, consider scoping results to the requesting user (pass `user` context) to reduce the default result set size.

### Proof of Concept

```
# Step 1: Authenticate and obtain a JWT token
POST /auth/login  { "email": "user@org.com", "password": "..." }
# → token

# Step 2: Repeatedly call the unbounded endpoint
GET /transaction-nodes?collection=HISTORY&network=testnet
Authorization: Bearer <token>

# As the transaction table grows (organic use or attacker-created transactions),
# each call fetches more rows. With tens of thousands of historical transactions,
# the Node.js process will exhaust heap memory or the DB will time out,
# returning 500 errors to all concurrent users.
```

The correlated subquery `SELECT COUNT(*)::int FROM transaction_group_item gi_all WHERE gi_all.groupId = rt.group_id` executes once per returned row, making the query O(N²) in the number of grouped transactions — accelerating the resource exhaustion. [8](#0-7)

### Citations

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

**File:** automation/k6/src/scripts/history.ts (L67-106)
```typescript
 * Main test function
 * Uses optimized /transaction-nodes endpoint - returns all items in single request
 */
export default function (data: MultiUserSetupData): void {
  const token = getTokenForVU(data);
  if (!token) return;

  const headers = authHeaders(token);
  const targetCount = DATA_VOLUMES.HISTORY; // 500

  group('History Page', () => {
    const startTime = Date.now();

    const res = http.get(
      `${BASE_URL}/transaction-nodes?collection=HISTORY&network=${NETWORK}`,
      { ...headers, tags: { name: 'history' } },
    );

    const totalDuration = Date.now() - startTime;
    totalDurationTrend.add(totalDuration);

    check(res, {
      'GET /transaction-nodes?collection=HISTORY → status 200': (r) => r.status === HTTP_STATUS.OK,
    });

    if (res.status !== HTTP_STATUS.OK) {
      dataVolumeOk.add(false);
      return;
    }

    try {
      const items = JSON.parse(res.body as string) as unknown[];
      const itemCount = items?.length ?? 0;

      dataVolumeOk.add(itemCount >= targetCount);

      check(null, {
        'GET /transaction-nodes?collection=HISTORY → response < 1s': () => totalDuration < THRESHOLDS.PAGE_LOAD_MS,
        [`GET /transaction-nodes?collection=HISTORY → fetched ${targetCount}+ items`]: () => itemCount >= targetCount,
      });
```

**File:** back-end/apps/api/src/users/users.service.ts (L86-96)
```typescript
  async getUsers(requestingUser: User): Promise<User[]> {
    // Only load clients relation when admin needs update info
    if (requestingUser.admin) {
      const users = await this.repo.find({ relations: ['clients'] });
      const latestSupported = this.configService.get<string>('LATEST_SUPPORTED_FRONTEND_VERSION');
      this.enrichUsersWithUpdateFlag(users, latestSupported);
      return users;
    }

    return this.repo.find();
  }
```
