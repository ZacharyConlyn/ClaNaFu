# ClaNaFu
Claude Names Functions: A Binary Ninja plugin

## What the heck is a ClaNaFu
ClaNaFu uses Claude to name functions in a given binary by providing it the decompiled pseudo C text of each function, the architecture, and binary format (so Claude can interpret syscall numbers, etc). It then updates the name of each function with Claude's analysis, in the format `llm_purpose_pct`, where `pct` is how confident Claude is in its analysis.

**Warning: Claude is OK at this job, but overestimates its own ability to interpret decompiled code!**

The functions are analyzed in order based on the call graph. Leaf functions are analyzed first, then each function is analyzed when all its callees have already been analyzed. This ensures Claude never has to see calls to unnamed functions. (The only exception is cycles, in that case I just send one function first to break the cycle).

It uses Claude's API, so you must have an API key and enough Claude Buxx (TM) to use it. I find it's about 1 cent or less per function analysis, but DO NOT just take my word for that!

You can enable batch mode in the settings, which should cut the monetary cost, but may increase the analysis times, as batch jobs are lower priority than normal API calls.

## Usage
0) Make sure you have the Anthropic Python library installed for Binary Ninja. You can easily install it by clicking `View -> Command Palette`, typing/selecting `install python3 module`, typing `anthropic` into the message box, and clicking `install`
1) Put clanafu.py in your Binary Ninja plugin folder and restart Binary Ninja
2) Load a binary to analyze, preferably one with lots of annoying library functions statically compiled in
3) Open the Binary Ninja settings, search for "ClaNaFu" or "api", and enter your Anthropic API key
4) In the menu, click `Plugins -> analyze functions`
5) Go get a cup of coffee, tea, beer, or milk: analysis takes about 2-3 seconds per function
6) Enjoy your named functions!
