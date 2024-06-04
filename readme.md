# DVSorder.py

This program illustrates and tests for the
[DVSorder vulnerability](https://DVSorder.org).

Given a Dominion CVR file (in CSV or zipped-JSON format) or ballot
image zip file, it attempts to unshuffle each batch of ballots. It
reports which batches are vulnerable and outputs an estimate of the
number of vulnerable ballots in the file.

Sample output:

```
$ ./DVSorder.py --cvrs testdata/v5-05-12-01_mi-wayne.zip
description: Wayne County 2020 November Election, version: 5.5.12.1
1057 of 1738 tabulators are vulnerable models
...
tabulator 2354 batch 0 appears vulnerable (1773 ballots, missing 2)
tabulator 2235 batch 0 appears vulnerable (1182 ballots, missing 0)
tabulator 1425 batch 0 appears vulnerable (473 ballots, missing 1)
tabulator 1431 batch 0 appears vulnerable (565 ballots, missing 0)
tabulator 1423 batch 0 appears vulnerable (593 ballots, missing 0)
tabulator 1429 batch 0 appears vulnerable (449 ballots, missing 0)
tabulator 1427 batch 0 appears vulnerable (559 ballots, missing 0)
tabulator 51 batch 0 appears vulnerable (616 ballots, missing 0)
tabulator 39 batch 0 appears vulnerable (548 ballots, missing 0)
tabulator 49 batch 0 appears vulnerable (728 ballots, missing 0)
tabulator 43 batch 0 appears vulnerable (472 ballots, missing 0)
tabulator 37 batch 0 appears vulnerable (575 ballots, missing 0)
tabulator 35 batch 0 appears vulnerable (707 ballots, missing 5)
...
approximately 22335 of 82403 ballots (27%) appear to be vulnerable
```
