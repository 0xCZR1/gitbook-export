---
hidden: true
---

# Case 3 - Season 1

## Understanding the problem:

* **08:17AM**: A gang of three armed men enter a bank located at 157th Ave / 148th Street and start collecting the money from the clerks.
* **08:31AM**: After collecting a decent loot (est. 1,000,000$ in cash), they pack up and get out.
* **08:40AM**: Police arrives at the crime scene, just to find out that it is too late, and the gang is not near the bank. The city is sealed - all vehicles are checked, robbers can't escape. Witnesses tell about a group of three men splitting into three different cars and driving away.
* **11:10AM**: After 2.5 hours of unsuccessful attempts to look around, the police decide to turn to us, so we can help in finding where the gang is hiding.

At first I tried to check whether or not the thieves used the same car/cars when entered and left, so I took the easiest route first:

```sql
let entryTraffic = Traffic
| where Timestamp between (datetime(2022-10-16 08:16:00) ..  datetime(2022-10-16 08:18:00))
| where Ave == 157 and Street == 148
| project EntryTime = Timestamp, EntryAve = Ave, EntryStreet = Street, VIN;
let exitTraffic = Traffic
| where Timestamp between (datetime(2022-10-16 08:30:00) ..  datetime(2022-10-16 08:32:00))
| where Ave == 157 and Street == 148
| project exitTime = Timestamp, exitAve = Ave, exitStreet = Street, VIN;
entryTraffic
| join kind = inner exitTraffic on VIN
| project
    VIN,
    EntryTime,
    exitTime,
    TimeDifference = exitTime - EntryTime
| order by TimeDifference asc
```

Unfortunately... this returned no results :(

<figure><img src="../.gitbook/assets/image (147).png" alt=""><figcaption></figcaption></figure>

So, now we know that they did not use the same cars to enter nor to leave... This suggests that the challenge is harder so let's widen our search by streets very close to the main bank street. If they left in different cars than those cars have to be somewhere parked and someone has had to park them. Let's try and find this.

```sql
let BankArea = Traffic
| where Ave between (156 .. 158) and Street between (147 .. 149)
| where Timestamp between (datetime(2022-10-16T08:31:00Z) .. datetime(2022-10-16T08:42:00Z))
| summarize count() by VIN;
Traffic
| where Timestamp > datetime(2022-10-16 08:33:00)
| summarize arg_max(Timestamp, *) by VIN
| join kind = inner BankArea on VIN
| summarize PossbileThieves = count() by Ave, Street
| where PossbileThieves == 3
```

And we got it :)&#x20;

<figure><img src="../.gitbook/assets/image (108).png" alt=""><figcaption></figcaption></figure>
