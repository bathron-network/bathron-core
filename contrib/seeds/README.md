# Seeds

Utility to turn a raw node list into the fixed-seed table compiled into the
client (`src/chainparamsseeds.h`).

Status: BATHRON launches with an EMPTY fixed-seed list (`vFixedSeeds` is empty
in `src/chainparamsseeds.h` — a deliberate launch item; nodes bootstrap from the
`addnode`/DNS entries in `chainparams.cpp` until a public seeder exists). This
tooling is kept ready to regenerate the table once a seed set is collected.

`PATTERN_AGENT` in `makeseeds.py` matches the current client user-agent
(`/BATHRON:0.9.x/`) — bump it when the client version changes and drop old ones.

Workflow (once `seeds_main.txt` / `seeds_test.txt` exist):

    python3 makeseeds.py < seeds_main.txt > nodes_main.txt
    python3 generate-seeds.py . > ../../src/chainparamsseeds.h

## Dependencies

Ubuntu:

    sudo apt-get install python3-dnspython
