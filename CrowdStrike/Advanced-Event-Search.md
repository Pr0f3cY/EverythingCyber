# 🔎 Advanced Event Search

## Hunting Queries

### 1. Command History Hunting

#### Objective

Detect suspicious command execution and discovery commands.

#### Query

```logscale
// Get CommandHistory and ProcessRollup2 events on Windows
#event_simpleName=/^(CommandHistory|ProcessRollup2)$/ event_platform=Win
| case{
    // Check to see if event name is CommandHistory
    #event_simpleName=CommandHistory
    // This is keyword list; modify as desired
    | CommandHistory=/(add|user|password|pass|stop|start)/i
    // This puts the CommandHistory entries into an array
    | CommandHistorySplit:=splitString(by="¶", field=CommandHistory)
    // This combines the array values and separates them with a new-line
    | concatArray("CommandHistorySplit", separator="\n", as=CommandHistoryClean);
    // Check to see if event name is ProcessRollup2. If yes, create mini process tree
    #event_simpleName="ProcessRollup2" | ExecutionChain:=format(format="%s\n\t└ %s (%s)", field=[ParentBaseFileName, FileName, RawProcessId]);
}
// Use selfJoinFilter to pair PR2 and CH events
| selfJoinFilter(field=[aid, TargetProcessId], where=[{#event_simpleName="ProcessRollup2"}, {#event_simpleName="CommandHistory"}])
// Aggregate to merge PR2 and CH events
| groupBy([aid, TargetProcessId], function=([collect([ProcessStartTime, ComputerName, UserName, UserSid, ExecutionChain, CommandHistoryClean])]), limit=max)
// Check to make sure CommandHistoryClean is populated due to non-deterministic nature of selfJoinFilter
| CommandHistoryClean=*
// OPTIONAL: exclude UserName values of administrators that are authorized
| !in(field="UserName", values=[userName1, userName2], ignoreCase=true)
// Format ProcessStartTime to human-readable
| ProcessStartTime:=ProcessStartTime*1000 | ProcessStartTime:=formatTime(format="%F %T.%L %Z", field="ProcessStartTime")
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
