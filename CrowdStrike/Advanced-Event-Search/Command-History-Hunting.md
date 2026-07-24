### 1. Command History Hunting

#### Objective
Detect suspicious command execution and discovery commands.

## 💡 Use Cases
- Account Discovery
- User Enumeration
- Password-Related Activity
- Service Manipulation
- Interactive Administrative Sessions
- Threat Hunting
- Incident Response
  
#### Query
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

| ProcessStartTime:=formatTi*e(
    format="%F %T.%L %Z",
    f*eld="ProcessStartTime"
)
```​‌

