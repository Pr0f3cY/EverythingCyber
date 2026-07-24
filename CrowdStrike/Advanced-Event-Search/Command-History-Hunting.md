# 🔎 Command History Hunting

## 🎯 Objective

Detect suspicious command execution on Windows systems by correlating `CommandHistory` and `ProcessRollup2` events.

This hunt helps identify users executing administrative, discovery, or potentially malicious commands while providing the associated process execution chain.

---

## 💡 Use Cases

- Account Discovery
- User Enumeration
- Password-Related Activity
- Service Manipulation
- Interactive Administrative Sessions
- Threat Hunting
- Incident Response

---

## 🧠 Query

```sql
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
    | concatArray("CommandHistorySplit",
        separator="\n",
        as=CommandHistoryClean);

    // Check to see if event name is ProcessRollup2.
    // If yes, create mini process tree
    #event_simpleName="ProcessRollup2"
    | ExecutionChain:=format(
        format="%s\n\t└ %s (%s)",
        field=[
            ParentBaseFileName,
            FileName,
            RawProcessId
        ]
    );
}

// Use selfJoinFilter to pair PR2 and CH events
| selfJoinFilter(
    field=[aid, TargetProcessId],
    where=[
        {#event_simpleName="ProcessRollup2"},
        {#event_simpleName="CommandHistory"}
    ]
)

// Aggregate to merge PR2 and CH events
| groupBy(
    [aid, TargetProcessId],
    function=([
        collect([
            ProcessStartTime,
            ComputerName,
            UserName,
            UserSid,
            ExecutionChain,
            CommandHistoryClean
        ])
    ]),
    limit=max
)

// Check to make sure CommandHistoryClean is populated
| CommandHistoryClean=*

// OPTIONAL: exclude authorized administrators
| !in(
    field="UserName",
    values=[userName1, userName2],
    ignoreCase=true
)

// Format ProcessStartTime to human-readable
| ProcessStartTime:=ProcessStartTime*1000

| ProcessStartTime:=formatTime(
    format="%F %T.%L %Z",
    field="ProcessStartTime"
)
```

---

## ⚙️ How It Works

### Step 1 - Collect Events

The query retrieves:

- `CommandHistory`
- `ProcessRollup2`

events from Windows endpoints.

---

### Step 2 - Filter Interesting Commands

The hunt focuses on commands containing:

```text
add
user
password
pass
stop
start
```

These keywords often appear during:

- Account administration
- Service manipulation
- Password changes
- User enumeration

---

### Step 3 - Correlate Events

The query uses:

```sql
selfJoinFilter()
```

to associate command history with the process responsible for execution.

---

### Step 4 - Build Execution Chain

A lightweight process tree is generated:

```text
cmd.exe
 └ net.exe (1234)
```

Example:

```text
powershell.exe
 └ net.exe (5124)
```

This provides valuable execution context during investigations.

---

### Step 5 - Filter Noise

The query optionally excludes known administrators:

```sql
| !in(field="UserName",
      values=[userName1,userName2],
      ignoreCase=true)
```

This can reduce false positives in enterprise environments.

---

## 📊 Example Output

| Field | Description |
|---------|---------|
| UserName | User executing the command |
| ComputerName | Affected endpoint |
| ExecutionChain | Parent-child process relationship |
| CommandHistoryClean | Command history contents |
| ProcessStartTime | Human-readable process start time |

---

## 🕵️ Investigation Tips

Review:

- Unusual users executing administrative commands
- Commands executed from PowerShell
- Service start/stop activity
- Password-related commands
- Discovery activity occurring shortly after logon

---

## 🚨 Potential False Positives

Common legitimate sources:

- Helpdesk Operations
- System Administrators
- Software Deployment Tools
- Automated Maintenance Scripts

Consider maintaining an allowlist of known administrative accounts.

---

## 🎯 MITRE ATT&CK Mapping

| Technique | Description |
|------------|------------|
| T1087 | Account Discovery |
| T1059 | Command and Scripting Interpreter |
| T1007 | System Service Discovery |
| T1033 | System Owner/User Discovery |

---

## 📝 Analyst Notes

This hunt is particularly valuable after:

- Initial access
- Privilege escalation
- Suspected hands-on-keyboard activity

Attackers frequently enumerate users, inspect services, and gather system information before moving laterally or attempting privilege escalation.

// Format ProcessStartTime to human-readable
| ProcessStartTime:=ProcessStartTime*1000

| ProcessStartTime:=formatTi*e(
    format="%F %T.%L %Z",
    f*eld="ProcessStartTime"
)
```​‌

