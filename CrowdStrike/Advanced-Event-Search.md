# 🔎 Advanced Event Search

## Hunting Queries

### 1. Command History Hunting

#### Objective

Detect suspicious command execution and discovery commands.

#### Query

```logscale
PASTE QUERY
```

#### Use Cases

- Account Discovery
- Reconnaissance
- Service Manipulation

---

### 2. Unsuccessful Logins Followed by Successful Login

#### Objective

Detect possible brute-force or password spray activity.

#### Query

```logscale
PASTE QUERY
```

#### Detection Logic

```text
3 Failed Logins
      ↓
Successful Login
      ↓
Within 10 Minutes
```

---

### 3. Four Or More Discovery Commands

#### Objective

Identify systems executing excessive discovery commands.

#### Query

```logscale
PASTE QUERY
```

---

### 4. Time Travel Detection

#### Objective

Identify impossible travel scenarios.

#### Query

```logscale
PASTE QUERY
```

---

### 5. Browser Extensions Installed

#### Objective

Identify potentially risky browser extensions.

#### Query

```logscale
PASTE QUERY
```
